# Anthropic submission checklist — TridentChain Security

Use before submitting the **plugin** or **Desktop extension (MCPB)**.

## Pre-flight (local)

- [ ] `pip install "tridentchain-security>=0.1.2" tridentchain-mcp`
- [ ] `python3 -c "from tridentchain_mcp.server import mcp; print(mcp.name)"`
- [ ] `tridentchain-security --scan project --project-path . --output-dir /tmp/tc-test`
- [ ] `claude plugin validate ./plugins/tridentchain-security` (if Claude Code installed)
- [ ] `./scripts/validate-plugin.sh`

## Plugin package

- [x] `plugin.json` — name, version `0.1.2`, description, author, category
- [x] `privacy_policies` HTTPS URL in `plugin.json`
- [x] [PRIVACY.md](PRIVACY.md) — data collection, retention, contact
- [x] Privacy section in [README.md](README.md)
- [x] [SECURITY.md](SECURITY.md) — reviewer notes
- [x] Skills: `supply-chain-scan`, `validate-fixes`
- [x] `.mcp.json` — stdio server
- [x] Icon: `.claude-plugin/icon.svg`

## MCP tools (directory technical requirements)

- [x] Each tool has `title` annotation
- [x] Each tool has `readOnlyHint` or `destructiveHint`
- [x] `validate_after_patch` — `readOnlyHint: true`
- [x] Scan tools — `readOnlyHint: false`, `destructiveHint: false`

## What to submit where

| Goal | Submit via |
|------|------------|
| **Claude plugin + skills** | [Plugin submission](https://claude.com/plugins) (see docs) |
| **Connectors Directory (remote)** | [MCP directory form](https://clau.de/mcp-directory-submission) — needs remote MCP + OAuth |
| **Claude Desktop one-click** | [Desktop extension / MCPB](https://clau.de/desktop-extention-submission) |

**This plugin is local-first.** Directory listing for PyPI-only MCP typically requires **MCPB** or **plugin** path, not remote directory alone.

## Copy-paste for submission form

See [docs/PLUGIN_SUBMISSION.md](../../docs/PLUGIN_SUBMISSION.md) for tagline, description, test steps, and tool list.

## After submission

- [ ] Bump `plugin.json` version when releasing updates
- [ ] Keep PyPI `tridentchain-mcp` compatible with `tridentchain-security>=0.1.2`
- [ ] Respond to `mcp-review@anthropic.com` if escalations needed
