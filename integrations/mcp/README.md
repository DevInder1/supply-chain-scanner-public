# Generic MCP configuration

Use this for **any MCP host** that accepts `mcpServers` JSON — Claude Desktop, Claude Code, Cursor, Windsurf, Continue, and others.

## Install options

### A) uvx — zero persistent install (recommended)

`uvx` runs the server in an isolated environment on demand. No manual `pip install` needed once `uv` is on PATH.

```bash
# Install uv (once)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Verify
uvx tridentchain-mcp --version
```

Config:

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "uvx",
      "args": ["tridentchain-mcp"]
    }
  }
}
```

### B) pip install — persistent global install

```bash
pip install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
```

Config (use the PATH entry point):

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

Or the portable `python3 -m` form (works even if the script isn't on PATH):

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

## Claude Code — project-level auto-discovery

Copy `.mcp.json` from the repo root into your project, or use the Claude Code UI:

```bash
claude mcp add tridentchain -- python3 -m tridentchain_mcp
```

## Tools

| Tool | readOnlyHint | Description |
|------|:------------:|-------------|
| `scan_project` | false | Project dependencies (fast) |
| `scan_full` | false | Project + OS packages + IDE extensions |
| `validate_after_patch` | true | Diff two scan JSON results |

See [docs/AGENT_INTEGRATIONS.md](../../docs/AGENT_INTEGRATIONS.md) for all agents.
