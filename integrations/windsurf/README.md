# Windsurf (Cascade) + TridentChain MCP

## Install

```bash
pip install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
```

## Configure

1. Command Palette → **Windsurf: Configure MCP Servers**
2. Merge into your global config at `~/.codeium/windsurf/mcp_config.json`:

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

3. **Restart Windsurf** fully.
4. In Cascade, ask to scan using **tridentchain** MCP tools.

## Tools

| Tool | Description |
|------|-------------|
| `scan_project` | Project dependencies only (fast) |
| `scan_full` | Project + OS packages + IDE extensions |
| `validate_after_patch` | Compare scans before/after upgrades |

Same tools and schema as Claude, Cursor, VS Code, and Zed.

## CLI fallback

If MCP is unavailable:

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

[Agent integrations hub](../../docs/AGENT_INTEGRATIONS.md)
