"""Unified tool layer for AI and IDE adapters (MCP, OpenAI, Cursor, etc.)."""

from scanner.integrations.schema import TOOL_SCHEMA_VERSION, get_tool_definitions
from scanner.integrations.unified import (
    AgentScanResult,
    execute_tool,
    scan_full,
    scan_project,
    validate_after_patch,
)

__all__ = [
    "TOOL_SCHEMA_VERSION",
    "AgentScanResult",
    "execute_tool",
    "get_tool_definitions",
    "scan_full",
    "scan_project",
    "validate_after_patch",
]
