"""Stdio MCP server exposing TridentChain Security unified tools."""

from __future__ import annotations

import json
import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP

from scanner.integrations import execute_tool
from tridentchain_mcp import __version__

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
    project_path: Annotated[str, "Absolute path to the project root (must contain package manifests)"],
    output_dir: Annotated[str | None, "Directory to write scan reports into (default: <project_path>/.tridentchain-out)"] = None,
    run_profile: Annotated[str, "Scan depth: 'quick' (fast/cached), 'full' (live advisory fetch), 'offline' (cache only)"] = "full",
    max_findings: Annotated[int, "Maximum number of affected packages to include in the findings list"] = 50,
) -> str:
    """Scan project dependencies for vulnerabilities (OSV, NVD, EPSS, etc.).

    Returns JSON with status, summary, and a findings list of affected packages.
    HTML reports are written to output_dir for browser review.
    """
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
    project_path: Annotated[str, "Absolute path to the project root"],
    output_dir: Annotated[str | None, "Directory to write scan reports into (default: <project_path>/.tridentchain-out)"] = None,
    run_profile: Annotated[str, "Scan depth: 'quick', 'full', or 'offline'"] = "full",
    max_findings: Annotated[int, "Maximum number of affected packages to include in the findings list"] = 50,
) -> str:
    """Full scan: project dependencies, OS/system packages, and IDE extensions.

    Broader than scan_project — also checks system-level packages and VS Code /
    JetBrains extensions for known CVEs. Writes HTML reports to output_dir.
    """
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
def validate_after_patch(
    baseline_json: Annotated[str, "JSON string from the pre-patch scan_project or scan_full result"],
    after_patch_json: Annotated[str, "JSON string from the post-patch scan_project or scan_full result"],
) -> str:
    """Compare a baseline scan vs a post-patch scan to confirm vulnerabilities are resolved.

    Returns resolved_count, remaining_count, new_count, and validation_passed (true only
    when new findings == 0 and at least one finding was resolved).
    """
    baseline = json.loads(baseline_json) if isinstance(baseline_json, str) else baseline_json
    after_patch = json.loads(after_patch_json) if isinstance(after_patch_json, str) else after_patch_json
    result = execute_tool(
        "validate_after_patch",
        {"baseline": baseline, "after_patch": after_patch},
    )
    return _json_result(result)


def main() -> None:
    """Run MCP server on stdio (Claude Desktop, Claude Code, Cursor, Windsurf, Zed)."""
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        print(f"tridentchain-mcp {__version__}")
        return
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
