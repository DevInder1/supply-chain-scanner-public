# Integration Roadmap

Goal: **keep `pip install tridentchain-security` + `tridentchain-security` CLI as the universal fallback**, while adding a unified tool layer for Claude, OpenAI, Cursor, VS Code, and Daybreak-style workflows.

---

## Phase 0 — Done

- [x] PyPI: `tridentchain-security`
- [x] npm: `@tridentchain/security-cli`
- [x] Python API: `run_scan()`
- [x] Docs: install, cross-platform, AI integration

---

## Phase 1 — Unified tool layer (in repo)

- [x] `scanner.integrations` module
- [x] Stable tool names + JSON schemas
- [x] `execute_tool()` dispatcher
- [x] Compact findings for LLM context
- [x] `validate_after_patch()` baseline diff

**CLI unchanged** — still calls `execute_scan()` directly.

---

## Phase 2 — Claude (official path)

- [x] `tridentchain-mcp` — PyPI-ready package; stdio MCP; wraps `execute_tool`
- [x] Plugin — `plugins/tridentchain-security/` (skills + `.mcp.json`)
- [x] Docs — [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md)

**Outcome:** Install MCP + plugin → Claude scans workspace without clone. Publish `tridentchain-mcp` to PyPI when ready.

**CLI unchanged:** `tridentchain-security` on PyPI remains the universal fallback.

---

## Phase 3 — OpenAI + Cursor

- [x] OpenAI adapter — `scanner.integrations.openai_adapter` (`to_openai_tools`, `run_openai_tool`)
- [x] Examples — `examples/openai/` (Chat Completions + Agents SDK)
- [x] Cursor MCP — `.cursor/mcp.json.example` + [CURSOR_SETUP.md](CURSOR_SETUP.md)
- [x] Cursor rule — `.cursor/rules/tridentchain.mdc`

**Outcome:** Same tools on OpenAI and Cursor; CLI fallback documented.

---

## Phase 4 — VS Code extension

- [x] Extension — `extensions/vscode-tridentchain/` (MCP-first, CLI fallback)
- [x] Commands — scan workspace / project, open report, validate after patch
- [x] Problems panel + findings webview
- [x] Workspace MCP example — `integrations/vscode/mcp.json.example`
- [x] Docs — [VSCODE_SETUP.md](VSCODE_SETUP.md) (Anthropic-aligned path)

**Outcome:** Same local `tridentchain-mcp` server as Claude/Cursor; no duplicate scan engine.

---

## Phase 5 — Daybreak-style validation UX

- [x] CLI `--validate` + `--baseline-report` / `--after-report` (additive; scan flags unchanged)
- [x] MCP `validate_after_patch` documented as first-class in [CAPABILITIES.md](CAPABILITIES.md)
- [x] Claude skill — upgrade-then-validate workflow in `validate-fixes`
- [x] Capabilities guide — [CAPABILITIES.md](CAPABILITIES.md)

**CLI unchanged for scans:** existing `tridentchain-security --scan …` behavior is identical.

---

## Phase 6 — Anthropic catalog (optional)

- [x] MCP tool annotations (`readOnlyHint`, titles) for directory review
- [x] Plugin submission pack ([PLUGIN_SUBMISSION.md](PLUGIN_SUBMISSION.md), checklist, validate script)
- [ ] **Submitted** to Anthropic plugin / connector process (manual step)
- [ ] MCP Bundle (MCPB) for Claude Desktop Extensions (optional)
- [ ] Remote MCP + OAuth only if claude.ai web users need hosted access

Status doc: [ANTHROPIC_ECOSYSTEM_STATUS.md](ANTHROPIC_ECOSYSTEM_STATUS.md)

---

## Non-goals (for now)

- Hosted multi-tenant scan API (remote MCP directory) — unless Phase 6 remote path chosen
- Replacing pip CLI with npm-only distribution
- Desktop Electron as agent entry point

---

## Success metrics

| Metric | Target |
|--------|--------|
| CLI install works without adapters | Always |
| One tool schema serves ≥3 platforms | MCP, OpenAI, Cursor |
| Agent token budget | &lt;50 findings default in unified response |
| No secrets in git | Continuous |
