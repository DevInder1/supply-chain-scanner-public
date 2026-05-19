"""Stable tool schemas for Claude MCP, OpenAI function calling, and other adapters."""

from __future__ import annotations

from typing import Any

TOOL_SCHEMA_VERSION = "1.0.0"

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "scan_project",
        "description": (
            "Scan project dependencies for supply-chain vulnerabilities. "
            "Uses OSV, NVD, and other sources. No API key required for default profile."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the project root",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory for scan-report.json and HTML reports",
                },
                "run_profile": {
                    "type": "string",
                    "enum": ["quick", "full", "offline"],
                    "default": "full",
                },
                "max_findings": {
                    "type": "integer",
                    "description": "Maximum findings returned to the model (default 50)",
                    "default": 50,
                },
            },
            "required": ["project_path"],
        },
    },
    {
        "name": "scan_full",
        "description": (
            "Full scan: project dependencies, system packages, and IDE extensions. "
            "Heavier than scan_project."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "output_dir": {"type": "string"},
                "run_profile": {
                    "type": "string",
                    "enum": ["quick", "full", "offline"],
                    "default": "full",
                },
                "max_findings": {"type": "integer", "default": 50},
            },
            "required": ["project_path"],
        },
    },
    {
        "name": "validate_after_patch",
        "description": (
            "Compare two scan summaries (baseline vs after patch) and report "
            "resolved, remaining, and new findings."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "baseline": {
                    "type": "object",
                    "description": "AgentScanResult or raw summary from first scan",
                },
                "after_patch": {
                    "type": "object",
                    "description": "AgentScanResult or raw summary from second scan",
                },
            },
            "required": ["baseline", "after_patch"],
        },
    },
]


def get_tool_definitions() -> list[dict[str, Any]]:
    """Return tool definitions for MCP, OpenAI, or other hosts."""
    return [dict(tool) for tool in TOOL_DEFINITIONS]
