# Anthropic submission checklist — TridentChain Security

Use before submitting the **plugin** or **Desktop extension (MCPB)**.

## Pre-flight (local) — verified 2026-05-22

- [x] `pip install "tridentchain-security>=0.1.2" "tridentchain-mcp>=0.1.1"`
- [x] `python3 -c "from tridentchain_mcp.server import mcp; print(mcp.name)"` → `tridentchain-security`
- [x] `tridentchain-security --scan project --project-path . --output-dir /tmp/tc-test`
- [x] `claude mcp add tridentchain -- python3 -m tridentchain_mcp` → Connected ✓
- [x] `claude mcp list` → `tridentchain: python3 -m tridentchain_mcp - ✓ Connected`
- [x] `claude plugin validate ./plugins/tridentchain-security` → PASSED (2 harmless warnings)
- [x] `./scripts/validate-plugin.sh` → All required checks passed
- [x] `tridentchain-security --version` → `tridentchain-security 0.1.2`
- [x] `tridentchain-mcp --version` → `tridentchain-mcp 0.1.1`
- [x] MCP stdio handshake → server name `tridentchain-security` ✓
- [x] `twine check` on both dist packages → PASSED
- [x] Both packages published to PyPI (`tridentchain-security==0.1.2`, `tridentchain-mcp==0.1.1`)

## Plugin package

- [x] `plugin.json` — name, version `0.1.2`, description, author, category
- [x] `privacy_policies` HTTPS URL in `plugin.json`
- [x] [PRIVACY.md](PRIVACY.md) — data collection, retention, contact
- [x] Privacy section in [README.md](README.md)
- [x] [SECURITY.md](SECURITY.md) — reviewer notes
- [x] Skills: `supply-chain-scan`, `validate-fixes`
- [x] `.mcp.json` — stdio server (`python3 -m tridentchain_mcp`)
- [x] Icon: `.claude-plugin/icon.svg`

## MCP tools (Anthropic technical requirements)

- [x] Each tool has `title` annotation
- [x] Each tool has `readOnlyHint` and `destructiveHint`
- [x] Each tool has `openWorldHint` where applicable
- [x] All tool parameters have `Annotated` descriptions (spec-compliant)
- [x] `validate_after_patch` — `readOnlyHint: true`
- [x] Scan tools — `readOnlyHint: false`, `destructiveHint: false`

## Client compatibility — all verified with `python3 -m tridentchain_mcp`

- [x] Claude Code — `claude mcp add` + plugin + project `.mcp.json`
- [x] Claude Desktop — `mcpServers` config (`python3 -m tridentchain_mcp`)
- [x] Cursor — `.cursor/mcp.json`
- [x] VS Code — `.vscode/mcp.json` (`"type": "stdio"`)
- [x] Windsurf — `~/.codeium/windsurf/mcp_config.json`
- [x] Zed — `context_servers` in `~/.config/zed/settings.json`
- [x] Generic MCP client — `integrations/mcp/mcpServers.json`

## What to submit where

| Goal | Submit via |
|------|------------|
| **Claude plugin + skills** | [Plugin submission](https://claude.com/plugins) — **primary path** |
| **Connectors Directory (remote)** | [MCP directory form](https://clau.de/mcp-directory-submission) — needs remote MCP + OAuth |
| **Claude Desktop one-click** | [Desktop extension / MCPB](https://clau.de/desktop-extention-submission) — Phase 6 optional |

**This plugin is local-first.** Use the plugin + skills path for submission.

## Copy-paste for submission form

See [docs/PLUGIN_SUBMISSION.md](../../docs/PLUGIN_SUBMISSION.md) for tagline, description, test steps, and tool list.

## After submission

- [ ] Bump `plugin.json` version when releasing updates
- [ ] Keep `tridentchain-mcp` compatible with `tridentchain-security>=0.1.2`
- [ ] Respond to `mcp-review@anthropic.com` for escalations
