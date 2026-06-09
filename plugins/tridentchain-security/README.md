# TridentChain Security — Claude Plugin

Local supply-chain vulnerability scanning for **Claude Code**, **Claude Desktop**, **Cursor**, **VS Code**, **Windsurf**, **Zed**, and any MCP client — via stdio MCP + skills.

[![PyPI](https://img.shields.io/pypi/v/tridentchain-security?label=tridentchain-security&color=3b82f6)](https://pypi.org/project/tridentchain-security/)
[![PyPI MCP](https://img.shields.io/pypi/v/tridentchain-mcp?label=tridentchain-mcp&color=3b82f6)](https://pypi.org/project/tridentchain-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/tridentchain-mcp?label=downloads&color=34d399)](https://pypi.org/project/tridentchain-mcp/)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-active-34d399)](https://registry.modelcontextprotocol.io/v0.1/servers?search=tridentchain)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](../../LICENSE)

## Install

```bash
pip install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
```

Verify:

```bash
tridentchain-security --version    # → tridentchain-security 0.1.2
tridentchain-mcp --version         # → tridentchain-mcp 0.1.1
python3 -c "from tridentchain_mcp.server import mcp; print(mcp.name)"
# → tridentchain-security
```

The **`tridentchain-security` CLI** is the universal fallback for any agent that can run shell commands.

---

## Claude Code

### Option 1 — One-liner (global, persists across projects)

```bash
claude mcp add tridentchain -- python3 -m tridentchain_mcp
```

### Option 2 — Plugin (skills + MCP, from repo root)

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
pip install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"
claude --plugin-dir ./plugins/tridentchain-security
```

Skills available after loading the plugin:

| Skill | Purpose |
|-------|---------|
| `/tridentchain-security:quick-scan` | Fast cached-only scan of project dependencies (sub-second) |
| `/tridentchain-security:scan` | Full project dependency scan with live OSV/NVD/GHSA advisories |
| `/tridentchain-security:scan-full` | Comprehensive: project deps + system packages + IDE extensions |
| `/tridentchain-security:why` | Explain why a vulnerable package is in the tree (chain, CVEs, EPSS, fix) |
| `/tridentchain-security:fix-plan` | EPSS/KEV-prioritised remediation plan with copy-paste upgrade commands |
| `/tridentchain-security:validate-fixes` | Re-scan and confirm fixes after dependency upgrades |
| `/tridentchain-security:supply-chain-scan` | General entry point — aliases `scan`, kept for backward compatibility |

### Option 3 — Project-level `.mcp.json` (auto-discovered)

Place in your project root and run `claude`:

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

---

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

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

Restart Claude Desktop and confirm **tridentchain** appears in the tools list.

---

## Cursor

Create `.cursor/mcp.json` in your project root:

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

---

## VS Code (GitHub Copilot agent mode)

Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "tridentchain": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "tridentchain_mcp"]
    }
  }
}
```

---

## Windsurf

Merge into `~/.codeium/windsurf/mcp_config.json`:

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

---

## Zed

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

---

## MCP tools

| Tool | Title | readOnlyHint | Description |
|------|-------|:------------:|-------------|
| `scan_project` | Scan Project Dependencies | false | Project deps only (fast) |
| `scan_full` | Scan Workspace (Full) | false | Project + OS packages + IDE extensions |
| `validate_after_patch` | Validate After Patch | true | Diff two scan results after upgrades |

Server: `tridentchain-mcp` (stdio transport). No API keys required for default profile.

---

## Privacy

TridentChain is **local-first**. Scans run on your machine; source code is never uploaded to TridentChain servers. Only package names/versions are sent to public advisory APIs (OSV, NVD).

Full policy: [PRIVACY.md](PRIVACY.md)  
HTTPS URL: `https://raw.githubusercontent.com/DevInder1/supply-chain-scanner-public/main/plugins/tridentchain-security/PRIVACY.md`

## Security

See [SECURITY.md](SECURITY.md).

## Validation (maintainers)

```bash
# From repo root
./scripts/validate-plugin.sh
claude plugin validate ./plugins/tridentchain-security
```

See [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md) and [docs/PLUGIN_SUBMISSION.md](../../docs/PLUGIN_SUBMISSION.md).

## Documentation

- [CLAUDE_MCP_SETUP.md](../../docs/CLAUDE_MCP_SETUP.md)
- [AGENT_INTEGRATIONS.md](../../docs/AGENT_INTEGRATIONS.md)
- [CURSOR_SETUP.md](../../docs/CURSOR_SETUP.md)
- [VSCODE_SETUP.md](../../docs/VSCODE_SETUP.md)

## License

MIT — see [LICENSE](../../LICENSE).
