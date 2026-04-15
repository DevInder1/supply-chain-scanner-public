"""NVD (National Vulnerability Database) source using CPE-based matching.

Queries the NVD 2.0 API to find CVEs for system packages by building
CPE 2.3 strings from the local package inventory.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

from scanner.core.sbom import Component
from scanner.storage.db import VulnerabilityDatabase

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

logger = logging.getLogger(__name__)

# Maps local package names to (vendor, product) for CPE construction.
# Covers Homebrew, Chocolatey, winget, dpkg, and rpm common names.
CPE_MAPPINGS: dict[str, tuple[str, str]] = {
    # Core libraries
    "openssl@3": ("openssl", "openssl"),
    "openssl": ("openssl", "openssl"),
    "sqlite": ("sqlite", "sqlite"),
    "sqlite3": ("sqlite", "sqlite"),
    "freetype": ("freetype", "freetype"),
    "harfbuzz": ("harfbuzz_project", "harfbuzz"),
    "icu4c": ("icu-project", "international_components_for_unicode"),
    "libpng": ("libpng", "libpng"),
    "libtiff": ("libtiff", "libtiff"),
    "zstd": ("facebook", "zstandard"),
    "pcre2": ("pcre", "pcre2"),
    "xz": ("tukaani", "xz"),
    "lz4": ("lz4_project", "lz4"),
    "cairo": ("cairographics", "cairo"),
    "jpeg-turbo": ("libjpeg-turbo", "libjpeg-turbo"),
    "jq": ("jqlang", "jq"),
    "oniguruma": ("oniguruma_project", "oniguruma"),
    "glib": ("gnome", "glib"),
    "little-cms2": ("littlecms", "little_cms_color_engine"),
    "giflib": ("giflib_project", "giflib"),
    "fontconfig": ("fontconfig_project", "fontconfig"),
    "ncurses": ("gnu", "ncurses"),
    "curl": ("haxx", "curl"),
    # Dev tools
    "git": ("git-scm", "git"),
    "git.install": ("git-scm", "git"),
    "kubernetes-cli": ("kubernetes", "kubernetes"),
    "vim": ("vim", "vim"),
    "neovim": ("neovim", "neovim"),
    "cmake": ("cmake", "cmake"),
    "wget": ("gnu", "wget"),
    # Runtimes
    "python": ("python", "python"),
    "python3": ("python", "python"),
    "python@3.10": ("python", "python"),
    "python@3.11": ("python", "python"),
    "python@3.12": ("python", "python"),
    "nodejs": ("nodejs", "node.js"),
    "nodejs.install": ("nodejs", "node.js"),
    "dotnet-sdk": ("microsoft", ".net"),
    "dotnet-runtime": ("microsoft", ".net"),
    "openjdk": ("oracle", "openjdk"),
    "temurin": ("oracle", "openjdk"),
    "corretto": ("oracle", "openjdk"),
    # Media / archive
    "ffmpeg": ("ffmpeg", "ffmpeg"),
    "imagemagick": ("imagemagick", "imagemagick"),
    "7zip": ("7-zip", "7-zip"),
    "7zip.install": ("7-zip", "7-zip"),
    # JetBrains IDEs
    "webstorm": ("jetbrains", "webstorm"),
    "intellij idea": ("jetbrains", "intellij_idea"),
    "intellij idea community": ("jetbrains", "intellij_idea"),
    "pycharm": ("jetbrains", "pycharm"),
    "pycharm community": ("jetbrains", "pycharm"),
    "clion": ("jetbrains", "clion"),
    "goland": ("jetbrains", "goland"),
    "phpstorm": ("jetbrains", "phpstorm"),
    "datagrip": ("jetbrains", "datagrip"),
    "rubymine": ("jetbrains", "rubymine"),
    "rider": ("jetbrains", "rider"),
    "dataspell": ("jetbrains", "dataspell"),
    "fleet": ("jetbrains", "fleet"),
    "aqua": ("jetbrains", "aqua"),
    "rustrover": ("jetbrains", "rustrover"),
}


def build_cpe(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 URI string."""
    safe_ver = _sanitize_cpe_component(version)
    return f"cpe:2.3:a:{vendor}:{product}:{safe_ver}:*:*:*:*:*:*:*"


def _sanitize_cpe_component(value: str) -> str:
    """Strip brew-style suffixes and clean version strings for CPE."""
    import re
    # Take only the first version token (before any comma or whitespace)
    v = value.strip().split(",")[0].split()[0]
    # Remove trailing _N build suffixes (e.g., 3.2.0_1 → 3.2.0)
    return re.sub(r"_\d+$", "", v)


def map_cpe(component: Component) -> str | None:
    """Return a CPE 2.3 string for a component, or None if no mapping exists."""
    name_lower = component.name.lower()
    mapping = CPE_MAPPINGS.get(name_lower)
    if not mapping:
        return None
    vendor, product = mapping
    return build_cpe(vendor, product, component.version)


def sync_nvd_advisories(
    components: list[Component],
    db: VulnerabilityDatabase,
    *,
    offline: bool,
    api_key: str | None = None,
    base_url: str = NVD_CVE_URL,
    timeout: int = 30,
) -> None:
    """Query NVD for CVEs matching each component's CPE."""
    if offline:
        return

    # Deduplicate queries by CPE
    cpe_to_names: dict[str, str] = {}
    for component in components:
        cpe = map_cpe(component)
        if cpe and component.name.lower() not in cpe_to_names.values():
            cpe_to_names[cpe] = component.name.lower()

    if not cpe_to_names:
        return

    # Skip packages already in cache — avoids slow re-fetches without an API key
    cached = set(db.nvd_lookup().keys())
    uncached = {cpe: name for cpe, name in cpe_to_names.items() if name not in cached}
    if not uncached:
        logger.info("NVD: all %d packages already cached, skipping API calls", len(cpe_to_names))
        return
    if cached:
        logger.info("NVD: %d cached, %d to fetch", len(cached & set(cpe_to_names.values())), len(uncached))

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    # NVD rate limit: 5 req/30s without key, 50 req/30s with key
    delay = 0.7 if api_key else 6.5
    if not api_key:
        logger.info("NVD: no API key — using slow rate limit (%.1fs/req). Set NVD_API_KEY in .env for 10x faster scans.", delay)

    for cpe, pkg_name in uncached.items():
        try:
            # Use keywordSearch as a reliable fallback — cpeName exact match
            # can miss when minor version components differ
            params: dict[str, Any] = {
                "cpeName": cpe,
                "resultsPerPage": 50,
            }
            response = requests.get(
                base_url,
                params=params,
                headers=headers,
                timeout=timeout,
            )
            if response.status_code == 403:
                logger.warning("NVD rate limit hit, backing off")
                time.sleep(30)
                continue
            response.raise_for_status()
            payload = response.json()

            cves = []
            for item in payload.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                # Extract useful fields
                metrics = cve_data.get("metrics", {})
                cvss_v31 = _extract_cvss_v31(metrics)
                descriptions = cve_data.get("descriptions", [])
                summary = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        summary = desc.get("value", "")
                        break

                cves.append({
                    "id": cve_id,
                    "cve_id": cve_id,
                    "summary": summary,
                    "severity": cvss_v31.get("severity", "UNKNOWN"),
                    "cvss_score": cvss_v31.get("score"),
                    "cvss_vector": cvss_v31.get("vector", ""),
                    "source": "nvd",
                    "references": [
                        {"url": ref.get("url", ""), "type": "WEB"}
                        for ref in cve_data.get("references", [])[:5]
                    ],
                })

            if cves:
                db.store_nvd_cves(pkg_name, cves)
                logger.info("NVD: %d CVEs for %s", len(cves), pkg_name)

        except requests.RequestException as exc:
            logger.warning("NVD query failed for %s: %s", pkg_name, exc)

        time.sleep(delay)


def _extract_cvss_v31(metrics: dict[str, Any]) -> dict[str, Any]:
    """Extract CVSS v3.1 base score and severity from NVD metrics."""
    for entry in metrics.get("cvssMetricV31", []):
        data = entry.get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": _nvd_severity(data.get("baseScore")),
            "vector": data.get("vectorString", ""),
        }
    # Fallback to v3.0
    for entry in metrics.get("cvssMetricV30", []):
        data = entry.get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": _nvd_severity(data.get("baseScore")),
            "vector": data.get("vectorString", ""),
        }
    # Fallback to v2
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": _nvd_severity_v2(data.get("baseScore")),
            "vector": data.get("vectorString", ""),
        }
    return {}


def _nvd_severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _nvd_severity_v2(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"
