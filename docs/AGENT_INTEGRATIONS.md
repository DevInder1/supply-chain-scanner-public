# Agent & IDE Integrations (All Platforms)

TridentChain uses **one engine** and **one tool schema** across every agent. Pick the path that matches your host.

```text
                    tridentchain-security (PyPI)
                              │
                    scanner.integrations
                     (scan_project, scan_full,
                      validate_after_patch)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        tridentchain-mcp   OpenAI tools    CLI / shell
        (stdio MCP)        (functions)     (universal)
              │
    Claude · Cursor · VS Code · Windsurf · Zed · …
```

**Install once (recommended):**

```bash
pip3 install "tridentchain-security>=0.1.2"
pip3 install tridentchain-mcp
```

**Universal fallback (every agent):** any host that can run shell commands → `tridentchain-security --scan all --project-path . --output-dir .tridentchain-out`

---

## Quick picker

| You use | Integration | Setup doc |
|---------|-------------|-----------|
| **Claude Desktop** | MCP `mcpServers` | [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md) |
| **Claude Code** | Plugin + MCP | [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md) · [plugin](../plugins/tridentchain-security/) |
| **Cursor** | MCP + rules | [CURSOR_SETUP.md](CURSOR_SETUP.md) |
| **VS Code** (Copilot / Agent) | MCP `servers` | [VSCODE_SETUP.md](VSCODE_SETUP.md) |
| **OpenAI** (API / Agents SDK) | Function tools | [examples/openai/](../examples/openai/) |
| **Windsurf** | MCP `mcpServers` | [integrations/windsurf/](../integrations/windsurf/) |
| **Zed** | MCP extension settings | [integrations/zed/](../integrations/zed/) |
| **Continue / Cline / other MCP** | stdio MCP | [integrations/mcp/](../integrations/mcp/) |
| **Custom / CI / any script** | CLI or Python API | [AI_INTEGRATION.md](AI_INTEGRATION.md) |
| **npm-only users** | CLI via wrapper | `npm i -g @tridentchain/security-cli` |

---

## Shared MCP server (Anthropic ecosystem + all MCP hosts)

**Package:** `tridentchain-mcp` on PyPI  
**Command:** `tridentchain-mcp` or `python3 -m tridentchain_mcp`

| Tool | Description |
|------|-------------|
| `scan_project` | Project dependencies |
| `scan_full` | Project + OS + IDE extensions |
| `validate_after_patch` | Compare scans after upgrades |

### MCP config by host

| Host | Config file | JSON key |
|------|-------------|----------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) | `mcpServers` |
| Claude Code (plugin) | `plugins/tridentchain-security/.mcp.json` | `mcpServers` |
| **Cursor** | `.cursor/mcp.json` | `mcpServers` |
| **VS Code** | `.vscode/mcp.json` | `servers` + `"type": "stdio"` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| **Zed** | `~/.config/zed/settings.json` (context_servers) | see [integrations/zed/](../integrations/zed/) |
| **Generic** | host-specific | copy [integrations/mcp/mcpServers.json](../integrations/mcp/mcpServers.json) |

**Portable command** (when `tridentchain-mcp` is not on PATH):

```json
"command": "python3",
"args": ["-m", "tridentchain_mcp"]
```

---

## OpenAI (Chat Completions, Assistants, Agents SDK)

OpenAI does **not** use MCP for TridentChain today — it uses the **same tool definitions** via `scanner.integrations.openai_adapter`:

```python
from scanner.integrations.openai_adapter import to_openai_tools, run_openai_tool

tools = to_openai_tools()
result = run_openai_tool("scan_project", {"project_path": ".", "output_dir": ".tridentchain-out"})
```

Runnable samples: [examples/openai/chat_completions_tools.py](../examples/openai/chat_completions_tools.py), [examples/openai/agents_sdk_sample.py](../examples/openai/agents_sdk_sample.py).

```bash
pip install openai
pip install openai-agents   # Agents SDK sample only
```

---

## Claude (Anthropic)

| Mode | Steps |
|------|--------|
| **Desktop** | Add `mcpServers.tridentchain` → restart → ask to scan |
| **Code + plugin** | `claude --plugin-dir ./plugins/tridentchain-security` |
| **Skills** | `/tridentchain-security:supply-chain-scan`, `validate-fixes` |

Details: [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md)

---

## Cursor

```bash
cp .cursor/mcp.json.example .cursor/mcp.json
# Enable rule: .cursor/rules/tridentchain.mdc
```

Details: [CURSOR_SETUP.md](CURSOR_SETUP.md)

---

## VS Code

- Repo includes [`.vscode/mcp.json`](../.vscode/mcp.json) — open folder and start MCP
- One-click: `./scripts/vscode-mcp-install-link.sh`
- Extension: [extensions/vscode-tridentchain/](../extensions/vscode-tridentchain/)

Details: [VSCODE_SETUP.md](VSCODE_SETUP.md)

---

## Other MCP-capable agents

Any client that supports **stdio MCP** can run `tridentchain-mcp`:

1. Point the host at `command: tridentchain-mcp` (or `python3 -m tridentchain_mcp`).
2. Restart the agent / reload MCP.
3. Invoke tools by name.

Examples in [integrations/](../integrations/) for Windsurf and Zed.

---

## Agent prompt snippet (copy into any chat)

```text
This workspace uses TridentChain Security for supply-chain scanning.

If MCP tools are available, use:
- scan_project — fast dependency scan
- scan_full — full scan (project + system + IDE)
- validate_after_patch — after dependency upgrades

Otherwise run:
  tridentchain-security --scan all --project-path <workspace> --output-dir .tridentchain-out

Read .tridentchain-out/scan-report.json. No API keys required for default profile.
```

Full text: [integrations/AGENT_PROMPT.txt](../integrations/AGENT_PROMPT.txt)

---

## Setup helper script

```bash
./scripts/setup-agent-mcp.sh claude   # prints config path + snippet
./scripts/setup-agent-mcp.sh cursor
./scripts/setup-agent-mcp.sh vscode
./scripts/setup-agent-mcp.sh windsurf
./scripts/setup-agent-mcp.sh openai   # OpenAI Python example path
```

---

## Version & compatibility

| Install | MCP | OpenAI tools | `--validate` CLI |
|---------|-----|--------------|------------------|
| `==0.1.0` | ❌ | ❌ | ❌ |
| `>=0.1.1` | ✅ | ✅ | ✅ |
| `>=0.1.2` (latest) | ✅ | ✅ | ✅ |

Pin older versions if you need frozen scan-only behavior.

---

## Related

- [CAPABILITIES.md](CAPABILITIES.md) — feature list
- [INTEGRATION_ARCHITECTURE.md](INTEGRATION_ARCHITECTURE.md) — design
- [AI_INTEGRATION.md](AI_INTEGRATION.md) — CLI & Python embedding
- [ROADMAP_INTEGRATIONS.md](ROADMAP_INTEGRATIONS.md)
