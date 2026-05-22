# Integration Architecture

TridentChain Security uses a **single core engine** with a **unified tool layer** and multiple **platform adapters**. The published pip CLI remains the universal fallback and is always supported.

```text
                    ┌─────────────────────────────────────┐
                    │   Core Vulnerability Engine       │
                    │   scanner/ + run_scan() / CLI       │
                    │   (PyPI: tridentchain-security)     │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │      Unified Tool Layer             │
                    │      scanner.integrations           │
                    │  • Stable tool names + JSON schema    │
                    │  • Agent-friendly findings payload    │
                    │  • validate_after_patch (diff)        │
                    └─────────────────┬───────────────────┘
                                      │
        ┌─────────────┬───────────────┼───────────────┬─────────────┐
        ▼             ▼               ▼               ▼             ▼
   Claude MCP    OpenAI Tools    Cursor Rules    VS Code ext   ChatGPT /
   + Plugin      (functions)     + MCP (opt)     (future)      Daybreak
```

---

## Layer 1 — Core engine (unchanged contract)

| Entry | Package | Role |
|-------|---------|------|
| `tridentchain-security` | PyPI CLI | Universal fallback; stdout JSON + reports |
| `run_scan()` | `scanner.api` | Python embedding |
| `execute_scan()` | `scanner.main` | Internal pipeline |

**Rule:** Adapters must call the unified layer or `run_scan()` — never fork matching logic.

---

## Layer 2 — Unified tool layer

Module: `scanner.integrations`

| Tool name | Description |
|-----------|-------------|
| `scan_project` | Project dependencies only (`--scan project`) |
| `scan_full` | Project + system + extensions (`--scan all`) |
| `get_tool_definitions` | JSON schemas for OpenAI / Claude tool registration |
| `execute_tool` | Dispatch by name (used by MCP servers) |

Normalized response shape (`AgentScanResult`):

- `status`, `summary`, `findings` (compact list), `output_paths`, `raw_summary`

See `scanner/integrations/unified.py`.

---

## Layer 3 — Platform adapters (roadmap)

| Platform | Adapter type | Status |
|----------|--------------|--------|
| **pip / shell** | CLI | Live |
| **Claude MCP** | Local stdio MCP → `execute_tool` | Live (`tridentchain-mcp` on PyPI) |
| **Claude Plugin** | Skills + connector ref | Live (`plugins/tridentchain-security/`) |
| **OpenAI** | Chat Completions tools / Agents SDK | Live (`examples/openai/`, `openai_adapter`) |
| **Cursor** | MCP + project rules + CLI | Live ([CURSOR_SETUP.md](CURSOR_SETUP.md)) |
| **VS Code** | Extension → local MCP + CLI fallback | Live ([VSCODE_SETUP.md](VSCODE_SETUP.md)) |
| **Windsurf / Zed / other MCP** | Same `tridentchain-mcp` stdio server | Live ([AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md)) |
| **Daybreak-style** | Detect → patch → `validate_after_patch` | Live (CLI `--validate` + MCP tool) |

---

## Claude / Anthropic official path

Per [Anthropic guidance](https://claude.com/docs/connectors/building/what-to-build):

1. **Local MCP server** (`tridentchain-mcp`) wrapping `scanner.integrations.execute_tool`
2. **Plugin** with skills: when to scan, how to read EPSS, how to re-scan after patch
3. **Directory connector** (optional later) only if offering hosted remote scans

Local MCP fits local-first security: code stays on the user's machine.

---

## OpenAI / ChatGPT path

Register the same tool definitions from `get_tool_definitions()`:

- OpenAI function calling
- Assistants API tools
- Agents SDK

No separate business logic.

---

## Cursor path

| Mode | Setup |
|------|--------|
| **Today** | Project rule + `tridentchain-security` CLI |
| **Next** | MCP server in `.cursor/mcp.json` |
| **Fallback** | Always CLI if MCP unavailable |

---

## VS Code path (Anthropic-aligned)

| Mode | Setup |
|------|--------|
| **Primary** | Extension → stdio `tridentchain-mcp` → `execute_tool` |
| **Workspace MCP** | `integrations/vscode/mcp.json.example` → `.vscode/mcp.json` |
| **Fallback** | Extension → `tridentchain-security` CLI |

Same MCP server name (`tridentchain`) and tool names as Claude Desktop and the Claude plugin `.mcp.json`.

---

## Validation loop (Daybreak-style)

```text
baseline = scan_full(project_path)
# agent or human applies dependency upgrades
verify = scan_full(project_path)
diff = validate_after_patch(baseline, verify)
```

Implemented in unified layer as comparison of finding keys (CVE + package + version).

---

## Versioning

| Artifact | Version field |
|----------|----------------|
| PyPI package | `scanner.__version__` |
| Tool schemas | `TOOL_SCHEMA_VERSION` in `scanner.integrations` |
| MCP / plugin | Pin to compatible tool schema version |

Breaking changes require major version bump on PyPI and coordinated adapter updates.

---

## Security principles (all adapters)

- No API keys in adapter bundles or plugin repos
- Secrets via environment / `.env` only
- Cap findings returned to models (`max_findings`)
- `project_path` must be user-controlled; no arbitrary shell from tool args

---

## Related docs

- [ROADMAP_INTEGRATIONS.md](ROADMAP_INTEGRATIONS.md) — phased delivery
- [AI_INTEGRATION.md](AI_INTEGRATION.md) — current agent usage
- [INSTALL_AND_USE.md](INSTALL_AND_USE.md) — pip/npm install
