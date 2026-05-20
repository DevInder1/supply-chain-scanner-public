# VS Code Setup (Phase 4) — Anthropic Ecosystem

TridentChain in VS Code follows the same **Anthropic-aligned** stack as Claude Desktop, Claude Code, and Cursor:

1. **Local stdio MCP server** — `tridentchain-mcp` → `scanner.integrations.execute_tool`
2. **Unified tool names** — `scan_project`, `scan_full`, `validate_after_patch`
3. **CLI fallback** — `tridentchain-security` (always available)

No hosted connector or forked scan logic.

---

## 1. Install Python packages

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

## 2. Install the VS Code extension (development)

```bash
cd extensions/vscode-tridentchain
npm install
npm run compile
```

In VS Code: **Extensions** → **…** → **Install from VSIX…** after `npm run package`, or **Run Extension** (F5) with `extensions/vscode-tridentchain` as the launch folder.

---

## 3. Optional: workspace MCP config

For VS Code builds with native MCP support, copy:

```bash
cp integrations/vscode/mcp.json.example .vscode/mcp.json
```

Same server definition as [Claude Desktop](CLAUDE_MCP_SETUP.md) and [Cursor](CURSOR_SETUP.md):

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

---

## 4. Commands

| Command | MCP tool | CLI equivalent |
|---------|----------|----------------|
| **TridentChain: Scan Workspace (Full)** | `scan_full` | `--scan all` |
| **TridentChain: Scan Project Dependencies** | `scan_project` | `--scan project` |
| **TridentChain: Open Scan Report** | — | opens `.tridentchain-out/scan-report.json` |
| **TridentChain: Validate After Patch** | `validate_after_patch` | local diff fallback |

Default: `tridentchain.preferMcp` = `true` (MCP first, then CLI).

---

## 5. Output

| Artifact | Location |
|----------|----------|
| JSON report | `.tridentchain-out/scan-report.json` |
| HTML reports | `.tridentchain-out/*.html` |
| Problems panel | Diagnostics on `package.json` / lockfile manifest |
| Webview | **TridentChain Findings** |

---

## 6. Claude plugin parity

The [Claude plugin](../plugins/tridentchain-security/) uses the same MCP server and skills. VS Code extension + plugin share:

- Tool schema version `TOOL_SCHEMA_VERSION` in `scanner.integrations`
- PyPI packages `tridentchain-security` + `tridentchain-mcp`

---

## Related

- [INTEGRATION_ARCHITECTURE.md](INTEGRATION_ARCHITECTURE.md) — Anthropic official path
- [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md)
- [CURSOR_SETUP.md](CURSOR_SETUP.md)
- [extensions/vscode-tridentchain/README.md](../extensions/vscode-tridentchain/README.md)
