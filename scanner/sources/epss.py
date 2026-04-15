from __future__ import annotations

from typing import Any

import requests

from scanner.storage.db import VulnerabilityDatabase

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def sync_epss_scores(
    cves: list[str],
    db: VulnerabilityDatabase,
    *,
    offline: bool,
    base_url: str = EPSS_API_URL,
    timeout: int = 30,
) -> None:
    if offline:
        return

    unique_cves = sorted({cve for cve in cves if cve and not db.has_epss_score(cve)})
    if not unique_cves:
        return

    for start in range(0, len(unique_cves), 100):
        chunk = unique_cves[start : start + 100]
        response = requests.get(
            base_url,
            params={"cve": ",".join(chunk)},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        for entry in payload.get("data", []):
            cve = entry.get("cve")
            if not cve:
                continue
            db.store_epss_score(
                cve=cve,
                score=_to_float(entry.get("epss")),
                percentile=_to_float(entry.get("percentile")),
                raw_payload=entry,
            )


def _to_float(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None