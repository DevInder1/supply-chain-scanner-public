# Zed + TridentChain MCP

## Install

```bash
pip install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
```

## Configure

Add to `~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "tridentchain": {
      "command": {
        "path": "python3",
        "args": ["-m", "tridentchain_mcp"]
      },
      "settings": {}
    }
  }
}
```

Restart Zed. The **tridentchain** context server should appear in the assistant panel.

## Tools

| Tool | Description |
|------|-------------|
| `scan_project` | Project dependencies only (fast) |
| `scan_full` | Project + OS packages + IDE extensions |
| `validate_after_patch` | Compare scans before/after upgrades |

## CLI fallback

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

[Agent integrations hub](../../docs/AGENT_INTEGRATIONS.md)
