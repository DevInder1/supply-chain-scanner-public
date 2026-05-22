# OpenAI + TridentChain

OpenAI agents use **function calling** (not MCP) with the same tool schemas as Claude MCP.

## Install

```bash
pip install "tridentchain-security>=0.1.2"
pip install openai
pip install openai-agents   # optional, for Agents SDK sample
```

## Code

```python
from scanner.integrations.openai_adapter import to_openai_tools, run_openai_tool

tools = to_openai_tools()
result = run_openai_tool("scan_project", {
    "project_path": "/path/to/repo",
    "output_dir": ".tridentchain-out",
})
```

## Examples

- [examples/openai/chat_completions_tools.py](../../examples/openai/chat_completions_tools.py)
- [examples/openai/agents_sdk_sample.py](../../examples/openai/agents_sdk_sample.py)

[Agent integrations hub](../../docs/AGENT_INTEGRATIONS.md)
