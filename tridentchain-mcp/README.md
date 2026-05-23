# tridentchain-mcp

<!-- mcp-name: io.github.DevInder1/tridentchain-security -->

MCP server for **TridentChain Security** — one local stdio server for **Claude, Cursor, VS Code, Windsurf, Zed**, and any MCP-compatible agent.

**Requires:** `pip install "tridentchain-security>=0.1.1"` (unified tool layer).

The **`tridentchain-security` CLI is unchanged** — universal fallback for any agent that runs shell commands.

## Install

```bash
pip install "tridentchain-security>=0.1.2"
pip install tridentchain-mcp
```

## Tools (all agents)

| Tool | Description |
|------|-------------|
| `scan_project` | Project dependencies only |
| `scan_full` | Project + system + extensions |
| `validate_after_patch` | Diff two scan JSON results |

## Quick config

**MCP hosts using `mcpServers`** (Claude, Cursor, Windsurf):

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "python3",
      "args": ["-m", "tridentchain_mcp"]
    }
  }
}
```

**VS Code** uses `"servers"` — see [integrations/vscode/mcp.json.example](../integrations/vscode/mcp.json.example).

**OpenAI** uses function calling (not MCP) — see [integrations/openai/](../integrations/openai/) and [examples/openai/](../examples/openai/).

## Agent setup

| Agent | Guide |
|-------|--------|
| All platforms | [docs/AGENT_INTEGRATIONS.md](../docs/AGENT_INTEGRATIONS.md) |
| Claude | [docs/CLAUDE_MCP_SETUP.md](../docs/CLAUDE_MCP_SETUP.md) |
| Cursor | [docs/CURSOR_SETUP.md](../docs/CURSOR_SETUP.md) |
| VS Code | [docs/VSCODE_SETUP.md](../docs/VSCODE_SETUP.md) |
| Helper script | `./scripts/setup-agent-mcp.sh <agent>` |

Copy-paste configs: [integrations/mcp/](../integrations/mcp/)
