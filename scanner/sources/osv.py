from __future__ import annotations

from collections import defaultdict
from typing import Any

import requests

from scanner.core.matcher import normalize_version
from scanner.core.sbom import Component
from scanner.storage.db import VulnerabilityDatabase

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{advisory_id}"


def sync_osv_advisories(
    components: list[Component],
    db: VulnerabilityDatabase,
    *,
    offline: bool,
    base_url: str = OSV_BATCH_URL,
    vuln_url: str = OSV_VULN_URL,
    timeout: int = 30,
) -> None:
    if offline:
        return

    grouped: dict[tuple[str, str], list[Component]] = defaultdict(list)
    for component in components:
        grouped[(component.name.lower(), component.ecosystem)].append(component)

    queries: list[dict[str, Any]] = []
    query_keys: list[tuple[str, str]] = []
    for _, group in grouped.items():
        representative = group[0]
        package_query = _build_query(representative)
        if not package_query:
            continue
        queries.append(package_query)
        query_keys.append((representative.name.lower(), representative.ecosystem))

    if not queries:
        return

    for start in range(0, len(queries), 100):
        batch_queries = queries[start : start + 100]
        batch_keys = query_keys[start : start + 100]
        response = requests.post(base_url, json={"queries": batch_queries}, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        results = payload.get("results", [])
        for index, result in enumerate(results):
            package_name, ecosystem = batch_keys[index]
            advisories = [
                _hydrate_advisory(vuln, vuln_url=vuln_url, timeout=timeout)
                for vuln in result.get("vulns", [])
            ]
            advisories = [advisory for advisory in advisories if advisory]
            db.store_package_advisories(package_name, ecosystem, advisories)


def _hydrate_advisory(
    advisory_stub: dict[str, Any],
    *,
    vuln_url: str,
    timeout: int,
) -> dict[str, Any] | None:
    advisory_id = advisory_stub.get("id")
    if not advisory_id:
        return None
    if advisory_stub.get("affected"):
        return advisory_stub

    response = requests.get(vuln_url.format(advisory_id=advisory_id), timeout=timeout)
    response.raise_for_status()
    return response.json()


def _build_query(component: Component) -> dict[str, Any] | None:
    ecosystem = map_osv_ecosystem(component)
    if not ecosystem:
        return None

    query: dict[str, Any] = {
        "package": {
            "name": map_osv_package_name(component),
            "ecosystem": ecosystem,
        }
    }

    normalized_version = normalize_version(component.version)
    if normalized_version and component.ecosystem in {"os", "vscode"}:
        # Don't send version for OSS-Fuzz: they use commit hashes, not release versions
        osv_eco = ecosystem
        if osv_eco != "OSS-Fuzz":
            query["version"] = normalized_version
    return query


def map_osv_ecosystem(component: Component) -> str | None:
    alias_ecosystem = str(component.metadata.get("osv_ecosystem") or "")
    if alias_ecosystem:
        return alias_ecosystem
    if component.ecosystem == "npm":
        return "npm"
    if component.ecosystem == "vscode":
        return "npm"
    if component.ecosystem == "os":
        return str(component.metadata.get("osv_ecosystem") or "") or None
    if component.ecosystem == "jetbrains":
        return None
    return component.ecosystem


def map_osv_package_name(component: Component) -> str:
    return str(component.metadata.get("osv_name") or component.name)


def supports_osv_query(component: Component) -> bool:
    return bool(map_osv_ecosystem(component))