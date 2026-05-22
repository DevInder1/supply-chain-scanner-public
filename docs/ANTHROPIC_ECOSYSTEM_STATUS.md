# Anthropic Ecosystem — What You Have vs What’s Next

This explains how TridentChain maps to [Anthropic’s connector guidance](https://claude.com/docs/connectors/building/what-to-build) and clears up **MCP vs “Anthropic tools.”**

---

## Short answer

| Question | Answer |
|----------|--------|
| **Is it already MCP?** | **Yes.** `tridentchain-mcp` is a real stdio MCP server on PyPI. |
| **Are MCP tools the same as “Anthropic tools”?** | **Yes, for Claude.** Claude calls your MCP **tools** (`scan_project`, etc.). There is no separate Anthropic-only tool API beyond MCP (for local/desktop). |
| **Is it “done” by Anthropic?** | **Not listed in Anthropic’s Connectors Directory.** You built the right *shape*; **directory listing** is a separate submission step. |
| **Do we need something else for OpenAI/Cursor/VS Code?** | **Same engine; different adapters.** OpenAI = function calling (`to_openai_tools`). Cursor/VS Code = same MCP server or CLI. |

---

## Anthropic’s three integration shapes

Per Anthropic docs, partners typically use one or more of:

```text
1. MCP server     → exposes TOOLS over the Model Context Protocol
2. Plugin         → skills + .mcp.json + distribution story for Claude Code/Desktop
3. Directory      → listed connector on claude.ai (often remote MCP + OAuth)
```

TridentChain today:

| Shape | Status | Your artifact |
|-------|--------|----------------|
| **1. Local MCP server** | ✅ Done | `tridentchain-mcp` (PyPI), FastMCP, stdio |
| **2. Plugin** | ✅ Built, not submitted | `plugins/tridentchain-security/` |
| **3. Directory connector** | ❌ Not started | Needs submission + usually remote/OAuth model |

**Important:** PyPI/npm **local** MCP servers are **not** listed directly in the Connectors Directory. Users install via `pip` or your **plugin** / **MCP Bundle (MCPB)**.

---

## What your MCP server already does (correct pattern)

`tridentchain-mcp` uses FastMCP and registers **three MCP tools**:

| MCP tool | Maps to |
|----------|---------|
| `scan_project` | `scanner.integrations.execute_tool` |
| `scan_full` | same unified layer |
| `validate_after_patch` | same unified layer |

That **is** the Anthropic-recommended local pattern:

- Local process (`tridentchain-mcp` or `python3 -m tridentchain_mcp`)
- stdio transport
- Tools with descriptions (model picks when to call them)
- Server `instructions` string (already set in `server.py`)

Claude Desktop / Claude Code / Cursor / VS Code do **not** need a different “Anthropic tool” format — they speak **MCP** and invoke these tool names.

---

## What is *not* the same thing

| Term | Meaning |
|------|---------|
| **MCP tool** | `scan_project` exposed by `tridentchain-mcp` — **you have this** |
| **OpenAI function tool** | Same logic, JSON schema via `to_openai_tools()` — **you have this** |
| **Claude plugin** | Skills + `.mcp.json` + packaging — **you have this in repo** |
| **Connectors Directory listing** | Anthropic’s public catalog on claude.ai — **you do not have this yet** |
| **Remote MCP + OAuth** | Hosted server for web Claude without local pip — **optional, not built** |
| **MCP Bundle (MCPB)** | Signed desktop extension for Claude Desktop gallery — **optional, not built** |

---

## Gap analysis (code vs Anthropic “publish”)

### Already aligned ✅

- Local-first MCP server wrapping one business layer (`execute_tool`)
- Plugin with `.mcp.json` pointing at `tridentchain-mcp`
- Skills for when to scan / validate
- No secrets in repo; local execution
- Published PyPI: `tridentchain-security`, `tridentchain-mcp`
- Cross-host docs (Claude, Cursor, VS Code, OpenAI, Windsurf)

### Nice-to-have for Anthropic submission polish

- [ ] MCP tool **annotations** (`readOnlyHint`, `title`) for auto-approve read-only tools in VS Code
- [ ] **Prompts** resource (optional MCP prompts as slash commands)
- [ ] Stricter **path sandbox** docs for `project_path` (security review)
- [ ] **Plugin version** aligned with PyPI (`plugin.json` vs `0.1.2`)

### Directory / official catalog (next product steps)

- [ ] **Submit plugin** to Anthropic’s plugin distribution path (follow current [submission docs](https://claude.com/docs/connectors/building/submission))
- [ ] **MCPB package** for Claude Desktop Extensions (if you want one-click Desktop without pip)
- [ ] **Remote MCP** only if you want claude.ai users without local install (conflicts with local-first unless hybrid)

---

## Recommended “what’s next” (in order)

### Tier 1 — No Anthropic approval needed (do now)

1. **Tell users to install:** `pip install tridentchain-security tridentchain-mcp`
2. **Claude Code:** `claude --plugin-dir ./plugins/tridentchain-security`
3. **Claude Desktop:** add `mcpServers` block (see [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md))
4. **Other agents:** [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md)

### Tier 2 — Anthropic ecosystem distribution

1. **Polish plugin** for marketplace submission (README, icons, version sync, security page)
2. **Submit plugin** per Anthropic connector/plugin submission checklist
3. Evaluate **MCPB** for Claude Desktop Extensions gallery

### Tier 3 — Only if you want cloud Claude users

1. Design **remote MCP** (HTTPS) + OAuth
2. Submit as **Directory connector** (different trust/review bar)

---

## Decision guide

```text
Keep local-first only?
  → You are DONE on architecture. Focus on plugin submission + docs + MCPB.

Want claude.ai web users without pip?
  → Add remote MCP + OAuth, then Directory submission.

Want OpenAI / Cursor / VS Code only?
  → MCP + openai_adapter + CLI is already sufficient.
```

---

## Related

- [INTEGRATION_ARCHITECTURE.md](INTEGRATION_ARCHITECTURE.md)
- [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md)
- [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md)
- [ROADMAP_INTEGRATIONS.md](ROADMAP_INTEGRATIONS.md)
