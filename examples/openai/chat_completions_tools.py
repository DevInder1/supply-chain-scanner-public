#!/usr/bin/env python3
"""
Minimal OpenAI Chat Completions example using TridentChain unified tools.

Usage:
  export OPENAI_API_KEY=sk-...
  python examples/openai/chat_completions_tools.py /path/to/project
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from openai import OpenAI

from scanner.integrations.openai_adapter import run_openai_tool, to_openai_tools

SYSTEM = (
    "You are a security assistant. Use scan_project for dependency-only scans "
    "or scan_full for project + system + IDE coverage. After dependency upgrades, "
    "use validate_after_patch with two prior scan payloads."
)


def run_agent_scan(project_path: str) -> None:
    client = OpenAI()
    tools = to_openai_tools()
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM},
        {
            "role": "user",
            "content": (
                f"Scan this project for supply-chain vulnerabilities: {project_path}. "
                "Use scan_project first with output_dir .tridentchain-out."
            ),
        },
    ]

    for _ in range(6):
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        choice = response.choices[0]
        message = choice.message
        if not message.tool_calls:
            print(message.content or "(no content)")
            return

        messages.append(message.model_dump(exclude_none=True))
        for call in message.tool_calls:
            name = call.function.name
            args = call.function.arguments or "{}"
            result = run_openai_tool(name, args)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": json.dumps(result, default=str),
                }
            )


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python chat_completions_tools.py <project_path>")
        sys.exit(1)
    project = str(Path(sys.argv[1]).resolve())
    run_agent_scan(project)


if __name__ == "__main__":
    main()
