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

| Deliverable | Description |
|-------------|-------------|
| `tridentchain-mcp` | PyPI package; stdio MCP; wraps `execute_tool` |
| Plugin repo | Skills + connector; GitHub distribution |
| Docs | Claude Desktop `mcp.json` example |

**Outcome:** Install MCP + plugin → Claude scans workspace without clone.

---

## Phase 3 — OpenAI + Cursor

| Deliverable | Description |
|-------------|-------------|
| OpenAI examples | Register `get_tool_definitions()` in Agents SDK sample |
| Cursor MCP config | Document `.cursor/mcp.json` |
| Cursor rule | Optional `.cursor/rules/tridentchain.md` |

**Outcome:** Same tools on OpenAI and Cursor; CLI fallback documented.

---

## Phase 4 — VS Code extension

- Command palette: “TridentChain: Scan workspace”
- Problems panel / webview for findings
- Uses `run_scan()` or MCP client to local server

---

## Phase 5 — Daybreak-style validation UX

- [ ] `tridentchain-security validate` CLI flag (optional)
- [ ] MCP tool `validate_after_patch` promoted to first-class UX
- [ ] Skill text for “upgrade then validate”

---

## Non-goals (for now)

- Hosted multi-tenant scan API (remote MCP directory)
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
