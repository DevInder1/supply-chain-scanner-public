# Generic MCP configuration

Use this for **any MCP host** that accepts Claude-style `mcpServers` JSON (Cursor, Claude Desktop, Windsurf, Continue, etc.).

## Install

```bash
pip install "tridentchain-security>=0.1.2" tridentchain-mcp
```

## Config

Copy [mcpServers.json](mcpServers.json) into your host’s MCP config, or merge the `tridentchain` block.

If `tridentchain-mcp` is on your PATH, you may use:

```json
"command": "tridentchain-mcp",
"args": []
```

## Tools

- `scan_project`
- `scan_full`
- `validate_after_patch`

See [docs/AGENT_INTEGRATIONS.md](../../docs/AGENT_INTEGRATIONS.md).
