"""Sonatype Guide source — vulnerability intelligence via Package URLs.

Queries the Sonatype Guide API (successor to OSS Index) to find
vulnerabilities for components by purl coordinates.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

from scanner.core.sbom import Component
from scanner.storage.db import VulnerabilityDatabase

GUIDE_API_URL = "https://api.guide.sonatype.com"

logger = logging.getLogger(__name__)

# Maps osv_ecosystem (or component.ecosystem) to purl type.
_PURL_TYPE_MAP: dict[str, str] = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "golang",
    "Maven": "maven",
    "NuGet": "nuget",
    "crates.io": "cargo",
    "RubyGems": "gem",
    "Packagist": "composer",
    "Debian": "deb",
    "Red Hat": "rpm",
}


def build_purl(component: Component) -> str | None:
    """Build a Package URL (purl) for a component, or return None."""
    osv_eco = str(component.metadata.get("osv_ecosystem", "")).strip()
    purl_type = _PURL_TYPE_MAP.get(osv_eco)
    if not purl_type:
        # Try component ecosystem directly
        purl_type = _PURL_TYPE_MAP.get(component.ecosystem)
    if not purl_type:
        if component.ecosystem == "vscode":
            purl_type = "npm"
        else:
            return None

    name = str(component.metadata.get("osv_name") or component.name)
    version = component.version.strip()
    if not version:
        return None

    # Maven uses group:artifact format — purl wants namespace/name
    if purl_type == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:{purl_type}/{group}/{artifact}@{version}"

    return f"pkg:{purl_type}/{name}@{version}"


def sync_ossindex_advisories(
    components: list[Component],
    db: VulnerabilityDatabase,
    *,
    offline: bool,
    sonatype_token: str | None = None,
    base_url: str = GUIDE_API_URL,
    timeout: int = 30,
) -> None:
    """Query Sonatype Guide for vulnerabilities by purl coordinates."""
    if offline:
        return

    if not sonatype_token:
        logger.info("Sonatype Guide: skipping (no SONATYPE_TOKEN configured)")
        return

    # Skip packages already in cache
    cached = set(db.ossindex_lookup().keys())

    # Build purl → component mapping (deduplicated)
    purl_map: dict[str, Component] = {}
    for component in components:
        purl = build_purl(component)
        if purl and purl not in purl_map and purl not in cached:
            purl_map[purl] = component

    if not purl_map:
        if cached:
            logger.info("Sonatype Guide: all %d packages already cached", len(cached))
        return

    headers = {
        "Authorization": f"Bearer {sonatype_token}",
        "User-Agent": "supply-chain-scanner/1.0",
    }

    logger.info("Sonatype Guide: querying %d components", len(purl_map))

    for purl, comp in purl_map.items():
        try:
            response = requests.get(
                f"{base_url}/components/vulnerabilities",
                params={"purl": purl},
                headers=headers,
                timeout=timeout,
            )
            if response.status_code == 401:
                logger.warning("Sonatype Guide: 401 Unauthorized — check SONATYPE_TOKEN. Skipping.")
                return
            if response.status_code == 404:
                # Package not in Sonatype database — expected for niche/proprietary packages
                continue
            if response.status_code == 429:
                logger.warning("Sonatype Guide: rate limited, backing off 30s")
                time.sleep(30)
                continue
            response.raise_for_status()
            payload = response.json()

            vulns = []
            for hit in payload.get("hits", []):
                vuln_id = hit.get("vulnId", "")
                if not vuln_id:
                    continue
                cvss_score = hit.get("cvssSeverity") or hit.get("sonatypeCvssSeverity")
                severity = _guide_severity(cvss_score)

                vulns.append({
                    "id": vuln_id,
                    "cve": vuln_id if vuln_id.startswith("CVE-") else None,
                    "summary": hit.get("summary", ""),
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cwes": hit.get("sonatypeCwes") or hit.get("cwes", []),
                    "is_malware": hit.get("isMalware", False),
                    "kev": hit.get("kev", False),
                    "epss": hit.get("epss"),
                    "source": "sonatype",
                    "references": [],
                })

            if vulns:
                db.store_ossindex_vulns(purl, vulns)
                logger.info("Sonatype Guide: %d vulns for %s", len(vulns), comp.name)

        except requests.RequestException as exc:
            logger.warning("Sonatype Guide query failed for %s: %s", comp.name, exc)

        # Small courtesy delay
        time.sleep(0.3)


def _guide_severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    try:
        score = float(score)
    except (TypeError, ValueError):
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
