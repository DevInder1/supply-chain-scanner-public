# TridentChain Security — Claude Plugin

Local supply-chain vulnerability scanning for **Claude Code** and **Claude Desktop** via MCP + skills.

[![PyPI](https://img.shields.io/pypi/v/tridentchain-security)](https://pypi.org/project/tridentchain-security/)
[![PyPI MCP](https://img.shields.io/pypi/v/tridentchain-mcp)](https://pypi.org/project/tridentchain-mcp/)

## Prerequisites

```bash
pip install "tridentchain-security>=0.1.2"
pip install tridentchain-mcp
```

Verify:

```bash
python3 -c "from tridentchain_mcp.server import mcp; print(mcp.name)"
```

The **`tridentchain-security` CLI** remains the universal fallback.

## Install (Claude Code)

From the public repository root:

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
claude --plugin-dir ./plugins/tridentchain-security
```

Or add this directory via **Claude Code plugin marketplaces** when published.

## Claude Desktop

Add to `claude_desktop_config.json`:

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

## Skills

| Skill | Invocation |
|-------|------------|
| Supply chain scan | `/tridentchain-security:supply-chain-scan` |
| Validate fixes | `/tridentchain-security:validate-fixes` |

## MCP tools

| Tool | Title | Read-only |
|------|-------|-----------|
| `scan_project` | Scan Project Dependencies | No (writes reports) |
| `scan_full` | Scan Workspace (Full) | No (writes reports) |
| `validate_after_patch` | Validate After Patch | Yes |

Server: `tridentchain-mcp` (stdio) via `.mcp.json`.

## Privacy Policy

TridentChain is **local-first**. Scans run on your machine; we do not host your source code.

Full policy: [PRIVACY.md](PRIVACY.md)  
HTTPS URL for directory submission:  
https://raw.githubusercontent.com/DevInder1/supply-chain-scanner-public/main/plugins/tridentchain-security/PRIVACY.md

## Security

See [SECURITY.md](SECURITY.md).

## Submission / validation

Maintainers: [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md) · [docs/PLUGIN_SUBMISSION.md](../../docs/PLUGIN_SUBMISSION.md)

```bash
# From repo root (requires Claude Code CLI)
claude plugin validate ./plugins/tridentchain-security
./scripts/validate-plugin.sh
```

## Documentation

- [CLAUDE_MCP_SETUP.md](../../docs/CLAUDE_MCP_SETUP.md)
- [AGENT_INTEGRATIONS.md](../../docs/AGENT_INTEGRATIONS.md)
- [ANTHROPIC_ECOSYSTEM_STATUS.md](../../docs/ANTHROPIC_ECOSYSTEM_STATUS.md)

## License

MIT — see [LICENSE](../../LICENSE).
