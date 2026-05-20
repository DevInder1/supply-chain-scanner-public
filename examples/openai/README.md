# OpenAI integration examples (Phase 3)

TridentChain uses the same tool schemas as Claude MCP via `scanner.integrations`.

## Prerequisites

```bash
pip install tridentchain-security>=0.1.1
pip install openai   # for these examples only
```

Optional Agents SDK:

```bash
pip install openai-agents
```

## Files

| File | Description |
|------|-------------|
| `chat_completions_tools.py` | Chat Completions tool loop with `to_openai_tools()` |
| `agents_sdk_sample.py` | OpenAI Agents SDK wiring (optional dependency) |

## CLI fallback

If tools are unavailable, agents should run:

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

See [docs/AI_INTEGRATION.md](../../docs/AI_INTEGRATION.md).
