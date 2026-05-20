# Claude & MCP Setup (Phase 2)

TridentChain Security Phase 2 adds **`tridentchain-mcp`** and a **Claude plugin**. The pip CLI **`tridentchain-security`** is unchanged.

---

## 1. Install

```bash
pip3 install tridentchain-security>=0.1.1
pip3 install tridentchain-mcp
```

Verify:

```bash
tridentchain-security --help
python3 -c "from tridentchain_mcp.server import mcp; print('MCP ready:', mcp.name)"
```

`tridentchain-mcp` is a stdio MCP server (no `--help`); hosts start it via `command: tridentchain-mcp`.

---

## 2. Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

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

Restart Claude Desktop. Ask: *"Scan this project for supply chain vulnerabilities using tridentchain."*

---

## 3. Claude Code — plugin

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
pip3 install -e .
pip3 install -e tridentchain-mcp
claude --plugin-dir ./plugins/tridentchain-security
```

Skills:

- `/tridentchain-security:supply-chain-scan`
- `/tridentchain-security:validate-fixes`

---

## 4. Cursor

Create `.cursor/mcp.json` in your project:

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

Reload Cursor MCP. CLI fallback still works:

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out
```

---

## 5. MCP tools

| Tool | Purpose |
|------|---------|
| `scan_project` | Fast project dependency scan |
| `scan_full` | Project + system + IDE extensions |
| `validate_after_patch` | Compare two scan JSON blobs after upgrades |

---

## 6. Fallback

If MCP is not configured, agents should use:

```bash
tridentchain-security --scan all --project-path <path> --output-dir .tridentchain-out
```

---

## Related

- [INTEGRATION_ARCHITECTURE.md](INTEGRATION_ARCHITECTURE.md)
- [ROADMAP_INTEGRATIONS.md](ROADMAP_INTEGRATIONS.md)
- [plugins/tridentchain-security/README.md](../plugins/tridentchain-security/README.md)
