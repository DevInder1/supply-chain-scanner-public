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
        "TridentChain Security is a local-first supply-chain vulnerability scanner that "
        "covers THREE surfaces other scanners miss: (1) project dependencies, (2) OS/system "
        "packages (Homebrew on macOS, apt/dnf on Linux), and (3) installed IDE extensions "
        "(VS Code, JetBrains). Findings are ranked by EPSS exploit probability and CISA "
        "KEV (Known Exploited Vulnerabilities) catalog presence — not just CVSS severity — "
        "so users see which CVEs to fix FIRST. "
        "Tool selection guide: use scan_project for fast project-only checks "
        "(npm/PyPI); use scan_full whenever the user asks for comprehensive coverage, "
        "system/Homebrew, or IDE extensions; use validate_after_patch after the user "
        "upgrades dependencies to confirm CVEs are resolved. "
        "No API keys required for default profiles. Source code never leaves the machine."
    ),
)


def _json_result(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, default=str)


@mcp.tool(
    annotations={
        "title": "Scan Project — EPSS/KEV-prioritised",
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
    """Scan project dependencies for CVEs and rank findings by REAL-WORLD EXPLOITATION
    RISK using EPSS (exploit probability) and the CISA KEV (Known Exploited
    Vulnerabilities) catalog — not just CVSS severity. Best for: when the user wants to
    know which CVEs to fix FIRST, asks about supply-chain risk in an IDE/conversational
    context, or wants to pair with validate_after_patch for a confirmed-fix workflow.
    Covers npm and PyPI manifests + lockfiles. For comprehensive coverage that also
    includes OS packages and IDE extensions, prefer scan_full. Returns JSON with status,
    EPSS-ranked findings list, and paths to HTML reports written under output_dir.
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
        "title": "Scan Workspace (Project + System + IDE)",
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
    """Comprehensive scan covering THREE surfaces in one call that project-only scanners
    cannot reach: (1) project dependencies (npm, PyPI), (2) OS/system packages
    (Homebrew on macOS, apt/dnf on Linux), and (3) installed IDE extensions
    (VS Code marketplace + JetBrains plugins). Use this whenever the user asks for
    "complete coverage", a "full audit", scanning their "whole machine" or "system",
    or wants to check IDE extensions — these are a growing attack vector and most
    other vulnerability scanners miss them entirely. Slower than scan_project; pick
    scan_project for fast project-only checks. Findings are ranked by EPSS exploit
    probability and CISA KEV presence so the user sees what attackers are actually
    using first. Returns JSON plus HTML reports under output_dir.
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
    """Confirm that dependency upgrades actually resolved the CVEs they were supposed
    to fix. Use this whenever the user says they ran `npm update`, `pip install -U`,
    or applied a patch and wants verification — chain it with two scan_project calls
    (before/after) or pass two saved scan JSON results. This is unique to TridentChain;
    most other supply-chain scanners only report findings without a verifiable
    post-patch loop. Returns resolved_count, remaining_count, new_count, and
    validation_passed (true only when new findings == 0 and at least one was resolved).
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
