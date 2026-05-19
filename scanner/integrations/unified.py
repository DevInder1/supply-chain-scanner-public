"""Unified tool execution — single entry point for all AI/IDE adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any, TypedDict

from scanner.api import run_scan


class AgentFinding(TypedDict, total=False):
    package: str
    version: str
    vulnerability_count: int
    severity: dict[str, int]


class AgentScanResult(TypedDict, total=False):
    status: str
    tool: str
    schema_version: str
    summary: Any
    findings: list[AgentFinding]
    output_paths: dict[str, str | None]
    report_path: str
    raw_summary: dict[str, Any]


def _normalize_summary(
    raw: dict[str, Any],
    *,
    tool: str,
    max_findings: int,
) -> AgentScanResult:
    from scanner.integrations.schema import TOOL_SCHEMA_VERSION

    affected = raw.get("affected_components") or []
    findings: list[AgentFinding] = []
    for item in affected[:max_findings]:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "package": str(item.get("name", "")),
                "version": str(item.get("version", "")),
                "vulnerability_count": int(item.get("vulnerabilities", 0)),
                "severity": dict(item.get("severity") or {}),
            }
        )
    output_paths = raw.get("output_paths") or {}
    return {
        "status": "ok",
        "tool": tool,
        "schema_version": TOOL_SCHEMA_VERSION,
        "summary": raw.get("summary"),
        "findings": findings,
        "output_paths": output_paths,
        "report_path": str(raw.get("report_path", "")),
        "raw_summary": raw,
    }


def scan_project(
    project_path: str,
    *,
    output_dir: str | None = None,
    run_profile: str = "full",
    max_findings: int = 50,
    **kwargs: Any,
) -> AgentScanResult:
    """Project-only scan — unified tool wrapper."""
    raw = run_scan(
        project_path=project_path,
        scan="project",
        run_profile=run_profile,
        output_dir=output_dir,
        **kwargs,
    )
    return _normalize_summary(raw, tool="scan_project", max_findings=max_findings)


def scan_full(
    project_path: str,
    *,
    output_dir: str | None = None,
    run_profile: str = "full",
    max_findings: int = 50,
    **kwargs: Any,
) -> AgentScanResult:
    """Full scan — unified tool wrapper."""
    raw = run_scan(
        project_path=project_path,
        scan="all",
        run_profile=run_profile,
        output_dir=output_dir or str(Path(project_path) / ".tridentchain-out"),
        **kwargs,
    )
    return _normalize_summary(raw, tool="scan_full", max_findings=max_findings)


def _finding_keys(raw: dict[str, Any]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for item in raw.get("affected_components") or []:
        if isinstance(item, dict):
            keys.add((str(item.get("name", "")), str(item.get("version", ""))))
    return keys


def validate_after_patch(
    baseline: dict[str, Any],
    after_patch: dict[str, Any],
) -> dict[str, Any]:
    """Diff two scan payloads for Daybreak-style patch validation."""
    base_raw = baseline.get("raw_summary") if "raw_summary" in baseline else baseline
    after_raw = after_patch.get("raw_summary") if "raw_summary" in after_patch else after_patch
    if not isinstance(base_raw, dict):
        base_raw = baseline
    if not isinstance(after_raw, dict):
        after_raw = after_patch

    before = _finding_keys(base_raw)
    after = _finding_keys(after_raw)
    resolved = before - after
    new = after - before
    remaining = before & after

    return {
        "status": "ok",
        "resolved_count": len(resolved),
        "remaining_count": len(remaining),
        "new_count": len(new),
        "resolved": [{"package": p, "version": v} for p, v in sorted(resolved)],
        "new_findings": [{"package": p, "version": v} for p, v in sorted(new)],
        "validation_passed": len(new) == 0 and len(resolved) > 0,
    }


def execute_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a unified tool by name (for MCP and other hosts)."""
    args = dict(arguments or {})
    if name == "scan_project":
        return scan_project(
            str(args["project_path"]),
            output_dir=args.get("output_dir"),
            run_profile=str(args.get("run_profile", "full")),
            max_findings=int(args.get("max_findings", 50)),
        )
    if name == "scan_full":
        return scan_full(
            str(args["project_path"]),
            output_dir=args.get("output_dir"),
            run_profile=str(args.get("run_profile", "full")),
            max_findings=int(args.get("max_findings", 50)),
        )
    if name == "validate_after_patch":
        return validate_after_patch(
            args["baseline"],
            args["after_patch"],
        )
    return {"status": "error", "message": f"Unknown tool: {name}"}
