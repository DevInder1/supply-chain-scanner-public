"""GitHub Advisory Database (GHSA) source via the GraphQL API.

Queries GHSA for security vulnerabilities by ecosystem and package name,
returning curated severity, CVSS scores, and fix versions.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

import requests

from scanner.core.sbom import Component
from scanner.storage.db import VulnerabilityDatabase

GHSA_GRAPHQL_URL = "https://api.github.com/graphql"

logger = logging.getLogger(__name__)

# Maps osv_ecosystem values to GHSA SecurityAdvisoryEcosystem enum values.
_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "NPM",
    "PyPI": "PIP",
    "Go": "GO",
    "Maven": "MAVEN",
    "NuGet": "NUGET",
    "crates.io": "RUST",
    "RubyGems": "RUBYGEMS",
    "Packagist": "COMPOSER",
}

_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $first: Int!) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: $first) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        publishedAt
        cvss { score vectorString }
        identifiers { type value }
        references { url }
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
      package { name ecosystem }
    }
  }
}
"""


def map_ghsa_ecosystem(component: Component) -> str | None:
    """Return the GHSA ecosystem enum value for a component, or None."""
    osv_eco = str(component.metadata.get("osv_ecosystem", "")).strip()
    if osv_eco in _ECOSYSTEM_MAP:
        return _ECOSYSTEM_MAP[osv_eco]
    comp_eco = component.ecosystem
    if comp_eco == "npm" or comp_eco == "vscode":
        return "NPM"
    return _ECOSYSTEM_MAP.get(comp_eco)


def map_ghsa_package_name(component: Component) -> str:
    """Return the package name to query in GHSA."""
    return str(component.metadata.get("osv_name") or component.name)


def supports_ghsa_query(component: Component) -> bool:
    return map_ghsa_ecosystem(component) is not None


def sync_ghsa_advisories(
    components: list[Component],
    db: VulnerabilityDatabase,
    *,
    offline: bool,
    github_token: str | None = None,
    base_url: str = GHSA_GRAPHQL_URL,
    timeout: int = 30,
    max_retries: int = 3,
) -> None:
    """Query GHSA for security vulnerabilities for each queryable component."""
    if offline or not github_token:
        if not github_token:
            logger.info("GHSA: skipping (no GITHUB_TOKEN configured)")
        return
    github_token = _normalize_github_token(github_token)
    if not github_token:
        logger.info("GHSA: skipping (GITHUB_TOKEN is empty after normalization)")
        return

    # Deduplicate by (ecosystem, package_name)
    grouped: dict[tuple[str, str], Component] = {}
    for component in components:
        ghsa_eco = map_ghsa_ecosystem(component)
        if not ghsa_eco:
            continue
        pkg_name = map_ghsa_package_name(component)
        key = (ghsa_eco, pkg_name)
        if key not in grouped:
            grouped[key] = component

    if not grouped:
        return

    headers = {
        "Authorization": f"bearer {github_token}",
        "Content-Type": "application/json",
    }

    if not _check_ghsa_auth(headers, base_url=base_url, timeout=timeout):
        logger.warning("GHSA: authentication failed (401). Verify local GITHUB_TOKEN value and permissions.")
        return

    for (ghsa_eco, pkg_name), component in grouped.items():
        try:
            variables = {
                "ecosystem": ghsa_eco,
                "package": pkg_name,
                "first": 100,
            }
            response = _post_with_retry(
                base_url=base_url,
                payload={"query": _QUERY, "variables": variables},
                headers=headers,
                timeout=timeout,
                max_retries=max_retries,
            )
            response.raise_for_status()
            payload = response.json()

            if "errors" in payload:
                logger.warning("GHSA GraphQL errors for %s: %s", pkg_name, payload["errors"])
                continue

            nodes = (
                payload.get("data", {})
                .get("securityVulnerabilities", {})
                .get("nodes", [])
            )

            advisories = []
            for node in nodes:
                advisory = node.get("advisory", {})
                ghsa_id = advisory.get("ghsaId")
                if not ghsa_id:
                    continue

                # Extract CVE from identifiers
                cve = None
                for ident in advisory.get("identifiers", []):
                    if ident.get("type") == "CVE":
                        cve = ident.get("value")
                        break

                cvss_data = advisory.get("cvss", {})
                severity = str(advisory.get("severity", "UNKNOWN")).upper()
                if severity == "MODERATE":
                    severity = "MEDIUM"

                fix_version = None
                patched = node.get("firstPatchedVersion")
                if patched:
                    fix_version = patched.get("identifier")

                advisories.append({
                    "id": ghsa_id,
                    "ghsa_id": ghsa_id,
                    "cve": cve,
                    "summary": advisory.get("summary", ""),
                    "severity": severity,
                    "cvss_score": cvss_data.get("score"),
                    "cvss_vector": cvss_data.get("vectorString", ""),
                    "published_at": advisory.get("publishedAt", ""),
                    "vulnerable_range": node.get("vulnerableVersionRange", ""),
                    "fix_version": fix_version,
                    "source": "ghsa",
                    "references": [
                        {"url": ref.get("url", ""), "type": "WEB"}
                        for ref in advisory.get("references", [])[:5]
                    ],
                })

            osv_eco = str(component.metadata.get("osv_ecosystem", component.ecosystem))
            if advisories:
                db.store_ghsa_advisories(pkg_name.lower(), osv_eco, advisories)
                logger.info("GHSA: %d advisories for %s/%s", len(advisories), ghsa_eco, pkg_name)

        except requests.RequestException as exc:
            logger.warning("GHSA query failed for %s/%s: %s", ghsa_eco, pkg_name, exc)


def _normalize_github_token(token: str) -> str:
    value = token.strip().strip("\"'")
    lowered = value.lower()
    if lowered.startswith("bearer "):
        return value[7:].strip()
    if lowered.startswith("token "):
        return value[6:].strip()
    return value


def _check_ghsa_auth(headers: dict[str, str], *, base_url: str, timeout: int) -> bool:
    """Fast preflight to avoid per-package 401 spam."""
    try:
        response = requests.post(
            base_url,
            json={"query": "query { viewer { login } }"},
            headers=headers,
            timeout=timeout,
        )
        if response.status_code == 401:
            return False
        response.raise_for_status()
        payload = response.json()
        return "errors" not in payload
    except requests.RequestException:
        return False


def _post_with_retry(
    *,
    base_url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: int,
    max_retries: int,
) -> requests.Response:
    attempt = 0
    while True:
        attempt += 1
        try:
            response = requests.post(
                base_url,
                json=payload,
                headers=headers,
                timeout=timeout,
            )
            if response.status_code in {502, 503, 504} and attempt <= max_retries:
                time.sleep(min(2 ** (attempt - 1), 8))
                continue
            return response
        except requests.Timeout:
            if attempt > max_retries:
                raise
            time.sleep(min(2 ** (attempt - 1), 8))
