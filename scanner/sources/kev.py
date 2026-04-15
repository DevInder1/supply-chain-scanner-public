from __future__ import annotations

import requests

from scanner.storage.db import VulnerabilityDatabase

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def sync_kev_catalog(
    db: VulnerabilityDatabase,
    *,
    offline: bool,
    url: str = KEV_URL,
    timeout: int = 30,
) -> None:
    if offline or db.kev_catalog_loaded():
        return

    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    for entry in payload.get("vulnerabilities", []):
        cve = entry.get("cveID")
        if not cve:
            continue
        db.store_kev_entry(cve, entry)
    db.mark_kev_catalog_loaded()