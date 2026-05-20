# TridentChain Security — Claude plugin

Official-style plugin bundle for Claude Code: **skills** + **local MCP** connector.

## Prerequisites

```bash
pip install tridentchain-security>=0.1.1 tridentchain-mcp
```

The **`tridentchain-security` CLI** remains the universal fallback.

## Install in Claude Code

From the repository root:

```bash
claude --plugin-dir ./plugins/tridentchain-security
```

Or add this folder via the plugin manager / marketplace when published.

## Skills

| Skill | Command namespace |
|-------|-------------------|
| Supply chain scan | `/tridentchain-security:supply-chain-scan` |
| Validate fixes | `/tridentchain-security:validate-fixes` |

## MCP

`.mcp.json` starts `tridentchain-mcp` (stdio) with tools: `scan_project`, `scan_full`, `validate_after_patch`.

See [docs/CLAUDE_MCP_SETUP.md](../../docs/CLAUDE_MCP_SETUP.md).
