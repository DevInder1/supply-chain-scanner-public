#!/usr/bin/env python3
"""
OpenAI Agents SDK sample — same tools as Claude MCP / Chat Completions.

Usage:
  pip install tridentchain-security openai-agents
  export OPENAI_API_KEY=sk-...
  python examples/openai/agents_sdk_sample.py /path/to/project
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    from agents import Agent, Runner, function_tool
except ImportError as exc:
    raise SystemExit(
        "Install the Agents SDK: pip install openai-agents"
    ) from exc

from scanner.integrations import execute_tool


@function_tool
def scan_project(
    project_path: str,
    output_dir: str | None = None,
    run_profile: str = "full",
    max_findings: int = 50,
) -> str:
    """Scan project dependencies for supply-chain vulnerabilities."""
    result = execute_tool(
        "scan_project",
        {
            "project_path": project_path,
            "output_dir": output_dir,
            "run_profile": run_profile,
            "max_findings": max_findings,
        },
    )
    return json.dumps(result, default=str)


@function_tool
def scan_full(
    project_path: str,
    output_dir: str | None = None,
    run_profile: str = "full",
    max_findings: int = 50,
) -> str:
    """Full scan: project, system packages, and IDE extensions."""
    result = execute_tool(
        "scan_full",
        {
            "project_path": project_path,
            "output_dir": output_dir,
            "run_profile": run_profile,
            "max_findings": max_findings,
        },
    )
    return json.dumps(result, default=str)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python agents_sdk_sample.py <project_path>")
        sys.exit(1)
    project_path = str(Path(sys.argv[1]).resolve())

    agent = Agent(
        name="TridentChain Security",
        instructions=(
            "You scan repositories for supply-chain vulnerabilities using "
            "scan_project or scan_full. Prefer scan_project for speed."
        ),
        tools=[scan_project, scan_full],
    )
    prompt = (
        f"Scan {project_path} for dependency vulnerabilities. "
        "Use scan_project with output_dir .tridentchain-out."
    )
    result = Runner.run_sync(agent, prompt)
    print(result.final_output)


if __name__ == "__main__":
    main()
