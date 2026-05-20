# tridentchain-mcp

MCP server for **TridentChain Security**. Exposes scan tools to Claude Desktop, Claude Code, Cursor, and other MCP hosts.

**Requires:** `pip install tridentchain-security>=0.1.1` (includes unified tool layer).

The **`tridentchain-security` CLI is unchanged** — use it as fallback when MCP is not configured.

## Install

```bash
pip install tridentchain-security tridentchain-mcp
```

## Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "tridentchain-mcp",
      "args": []
    }
  }
}
```

## Cursor (`.cursor/mcp.json` in project root)

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "tridentchain-mcp",
      "args": []
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_project` | Project dependencies only |
| `scan_full` | Project + system + extensions |
| `validate_after_patch` | Diff two scan JSON results |

See [docs/CLAUDE_MCP_SETUP.md](../docs/CLAUDE_MCP_SETUP.md) and the Claude plugin in `plugins/tridentchain-security/`.
