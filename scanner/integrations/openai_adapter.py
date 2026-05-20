"""Convert unified tool definitions to OpenAI function-calling format."""

from __future__ import annotations

from typing import Any

from scanner.integrations.schema import get_tool_definitions


def to_openai_tools(definitions: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Map TridentChain tool schemas to OpenAI Chat Completions / Responses tools."""
    defs = definitions if definitions is not None else get_tool_definitions()
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": dict(tool["input_schema"]),
            },
        }
        for tool in defs
    ]


def run_openai_tool(name: str, arguments: str | dict[str, Any]) -> dict[str, Any]:
    """Execute a tool call from an OpenAI model response."""
    import json

    from scanner.integrations import execute_tool

    if isinstance(arguments, str):
        parsed: dict[str, Any] = json.loads(arguments) if arguments.strip() else {}
    else:
        parsed = dict(arguments)
    return execute_tool(name, parsed)
