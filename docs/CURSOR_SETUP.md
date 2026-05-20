# Cursor Setup (Phase 3)

Use TridentChain Security in Cursor via **MCP** (recommended) or the **CLI fallback**.

---

## 1. Install

```bash
pip3 install "tridentchain-security>=0.1.1"
pip3 install tridentchain-mcp
```

Verify:

```bash
tridentchain-security --help
python3 -c "from tridentchain_mcp.server import mcp; print('MCP:', mcp.name)"
```

---

## 2. Enable MCP in your project

Copy the example config:

```bash
cp .cursor/mcp.json.example .cursor/mcp.json
```

Or create `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "tridentchain": {
      "command": "tridentchain-mcp",
      "args": []
    }
  }
}
```

Reload MCP in Cursor (Settings → MCP, or restart). Then ask the agent to scan the workspace using TridentChain tools.

---

## 3. Project rule (optional)

This repo includes [`.cursor/rules/tridentchain.mdc`](../.cursor/rules/tridentchain.mdc) — enable it in Cursor Rules when you want scan/validate guidance without repeating prompts.

---

## 4. CLI fallback

If MCP is unavailable:

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

The agent should read `.tridentchain-out/scan-report.json`.

---

## MCP tools

| Tool | Purpose |
|------|---------|
| `scan_project` | Project dependencies only |
| `scan_full` | Project + system + IDE extensions |
| `validate_after_patch` | Diff two scan payloads after upgrades |

---

## OpenAI (same schemas)

See [examples/openai/](../examples/openai/) for Chat Completions and Agents SDK samples using `scanner.integrations.openai_adapter`.

---

## Related

- [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md) — Claude Desktop / Code
- [AI_INTEGRATION.md](AI_INTEGRATION.md) — all agent paths
- [INTEGRATION_ARCHITECTURE.md](INTEGRATION_ARCHITECTURE.md)
