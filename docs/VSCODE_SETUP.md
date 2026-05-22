# VS Code — TridentChain as MCP (Anthropic Ecosystem)

TridentChain uses the **Model Context Protocol (MCP)** — the open standard from **Anthropic** for connecting AI assistants to local tools. The same pattern is used by:

| Host | Config file | Server |
|------|-------------|--------|
| **VS Code** (Copilot / Agent) | `.vscode/mcp.json` | `tridentchain-mcp` |
| **Claude Desktop** | `claude_desktop_config.json` | `tridentchain-mcp` |
| **Claude Code** | plugin `.mcp.json` | `tridentchain-mcp` |
| **Cursor** | `.cursor/mcp.json` | `tridentchain-mcp` |

TridentChain implements Anthropic’s recommended **local stdio MCP server** (not a hosted connector): scans stay on your machine.

References: [Anthropic — What to build](https://docs.anthropic.com/en/docs/agents-and-tools/mcp) · [Model Context Protocol](https://modelcontextprotocol.io/) · [VS Code MCP docs](https://code.visualstudio.com/docs/copilot/customization/mcp-servers)

---

## 1. Install (PyPI)

```bash
pip3 install "tridentchain-security>=0.1.2"
pip3 install tridentchain-mcp
```

Verify the MCP server starts:

```bash
python3 -c "from tridentchain_mcp.server import mcp; print('MCP server:', mcp.name)"
# Expect: tridentchain-security
```

Ensure `tridentchain-mcp` is on your PATH (same Python you used for `pip3 install`). If not, use the `python3 -m` config below.

---

## 2. Easiest ways to enable MCP in VS Code

### Option A — Open this repo (zero config)

This repository includes **`.vscode/mcp.json`** already. Open the folder in VS Code → **`MCP: List Servers`** → start **tridentchain**.

### Option B — One-click install link

After `pip install tridentchain-mcp`, run:

```bash
./scripts/vscode-mcp-install-link.sh
```

Open the printed `vscode:mcp/install?...` link (or paste in browser). VS Code adds the server globally.

### Option C — TridentChain VS Code extension

Install / run the extension (`extensions/vscode-tridentchain/`):

- Command Palette → **`TridentChain: Add MCP Server (One-Click Install)`**
- Or → **`TridentChain: Setup MCP in This Workspace`** (writes `.vscode/mcp.json`)

The extension also registers MCP under **Extensions → MCP Servers** automatically (VS Code 1.102+).

### Option D — Manual workspace config

In your project root:

```bash
mkdir -p .vscode
cp integrations/vscode/mcp.json.example .vscode/mcp.json
```

Or create **`.vscode/mcp.json`** manually:

```json
{
  "servers": {
    "tridentchain": {
      "type": "stdio",
      "command": "tridentchain-mcp",
      "args": []
    }
  }
}
```

### Option B — `python3 -m` (if `tridentchain-mcp` is not on PATH)

```bash
cp integrations/vscode/mcp.python3.json.example .vscode/mcp.json
```

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

### Option C — User-wide (all workspaces)

1. Command Palette → **`MCP: Open User Configuration`**
2. Paste the same `servers.tridentchain` block into your user `mcp.json`.

---

## 3. Start the server in VS Code

1. Open the project folder in VS Code.
2. Command Palette → **`MCP: List Servers`** — confirm **tridentchain** appears.
3. Start or restart the server if needed (**MCP: List Servers** → Start).
4. Open **Copilot Chat** or **Agent** mode (VS Code 1.102+ with MCP enabled).
5. Ensure MCP tools are allowed: setting **`chat.mcp.access`**.

Ask the agent, for example:

> Scan this workspace for supply-chain vulnerabilities using the tridentchain MCP tools. Start with scan_project and write reports to .tridentchain-out.

---

## 4. MCP tools (same as Claude / Cursor)

| Tool | Use when |
|------|----------|
| `scan_project` | Fast scan — project dependencies only |
| `scan_full` | Full scan — project + OS packages + IDE extensions |
| `validate_after_patch` | After upgrades — compare two scan JSON payloads |

Reports are written under `.tridentchain-out/` (or the `output_dir` you pass).

---

## 5. CLI fallback (always works)

If MCP is not enabled in your VS Code build:

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

---

## 6. Optional: TridentChain VS Code extension

The repo extension (`extensions/vscode-tridentchain/`) adds Command Palette actions and a findings webview. It uses the **same** `tridentchain-mcp` server internally. Native `.vscode/mcp.json` is enough for Copilot/Agent MCP tools without installing the extension.

---

## 7. Sandboxing (optional)

VS Code can run MCP servers in a sandbox. TridentChain needs read access to the workspace and network for advisory APIs. Example:

```json
{
  "servers": {
    "tridentchain": {
      "type": "stdio",
      "command": "tridentchain-mcp",
      "args": [],
      "sandboxEnabled": true,
      "sandbox": {
        "filesystem": {
          "allowWrite": ["${workspaceFolder}"]
        },
        "network": {
          "allowedDomains": ["api.osv.dev", "services.nvd.nist.gov", "*.githubusercontent.com"]
        }
      }
    }
  }
}
```

Adjust domains if you use extra sources (GHSA, Sonatype).

---

## Claude plugin parity

The [Claude plugin](../plugins/tridentchain-security/) registers the same MCP server and skills (`supply-chain-scan`, `validate-fixes`). One install (`tridentchain-mcp`) serves VS Code, Claude, and Cursor.

---

## Related

- [CAPABILITIES.md](CAPABILITIES.md) — full feature list
- [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md) — Claude Desktop / Code
- [CURSOR_SETUP.md](CURSOR_SETUP.md) — Cursor
- [INTEGRATION_ARCHITECTURE.md](INTEGRATION_ARCHITECTURE.md)
