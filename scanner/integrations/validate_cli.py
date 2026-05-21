"""Load scan JSON files for CLI validate mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_scan_payload(path: str | Path) -> dict[str, Any]:
    """Load a scan summary or full report JSON for validate_after_patch."""
    file_path = Path(path).expanduser().resolve()
    if not file_path.is_file():
        raise ValueError(f"report file not found: {file_path}")
    data = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object in {file_path}")

    if "affected_components" in data:
        return data

    if "vulnerabilities" in data:
        vulns = data.get("vulnerabilities") or []
        return {
            "affected_components": [
                {
                    "name": str(entry.get("component", {}).get("name", "")),
                    "version": str(entry.get("component", {}).get("version", "")),
                    "vulnerabilities": len(entry.get("advisories") or []),
                }
                for entry in vulns
                if isinstance(entry, dict)
            ],
            "report_path": str(file_path),
        }

    raise ValueError(
        f"{file_path} must contain 'affected_components' (CLI summary) or 'vulnerabilities' (full report)"
    )
