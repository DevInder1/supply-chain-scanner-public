"""Stdio MCP server exposing TridentChain Security unified tools."""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from scanner.integrations import execute_tool

mcp = FastMCP(
    "tridentchain-security",
    instructions=(
        "TridentChain Security scans project dependencies and optionally system/IDE "
        "components for supply-chain vulnerabilities. Use scan_project for fast "
        "project-only scans; scan_full for complete coverage. After dependency "
        "upgrades, run scan again and use validate_after_patch with baseline and "
        "after_patch summaries. No API keys required for default profiles."
    ),
)


def _json_result(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, default=str)


@mcp.tool(
    annotations={
        "title": "Scan Project Dependencies",
        "readOnlyHint": False,
        "destructiveHint": False,
        "openWorldHint": True,
    }
)
def scan_project(
    project_path: str,
    output_dir: str | None = None,
    run_profile: str = "full",
    max_findings: int = 50,
) -> str:
    """Scan project dependencies for vulnerabilities (OSV, NVD, etc.)."""
    result = execute_tool(
        "scan_project",
        {
            "project_path": project_path,
            "output_dir": output_dir,
            "run_profile": run_profile,
            "max_findings": max_findings,
        },
    )
    return _json_result(result)


@mcp.tool(
    annotations={
        "title": "Scan Workspace (Full)",
        "readOnlyHint": False,
        "destructiveHint": False,
        "openWorldHint": True,
    }
)
def scan_full(
    project_path: str,
    output_dir: str | None = None,
    run_profile: str = "full",
    max_findings: int = 50,
) -> str:
    """Full scan: project dependencies, system packages, and IDE extensions."""
    result = execute_tool(
        "scan_full",
        {
            "project_path": project_path,
            "output_dir": output_dir or f"{project_path.rstrip('/')}/.tridentchain-out",
            "run_profile": run_profile,
            "max_findings": max_findings,
        },
    )
    return _json_result(result)


@mcp.tool(
    annotations={
        "title": "Validate After Patch",
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    }
)
def validate_after_patch(baseline_json: str, after_patch_json: str) -> str:
    """Compare baseline vs post-patch scan JSON (from scan_project or scan_full)."""
    baseline = json.loads(baseline_json) if isinstance(baseline_json, str) else baseline_json
    after_patch = json.loads(after_patch_json) if isinstance(after_patch_json, str) else after_patch_json
    result = execute_tool(
        "validate_after_patch",
        {"baseline": baseline, "after_patch": after_patch},
    )
    return _json_result(result)


def main() -> None:
    """Run MCP server on stdio (Claude Desktop, Claude Code, Cursor)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
