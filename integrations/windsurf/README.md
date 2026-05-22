# Windsurf (Cascade) + TridentChain MCP

1. `pip install "tridentchain-security>=0.1.2" tridentchain-mcp`
2. Command Palette → **Windsurf: Configure MCP Servers**
3. Merge [mcp_config.json.example](mcp_config.json.example) into your global config:
   - macOS/Linux: `~/.codeium/windsurf/mcp_config.json`
4. **Restart Windsurf** fully.
5. In Cascade, ask to scan using **tridentchain** MCP tools.

Same tools as Claude and Cursor: `scan_project`, `scan_full`, `validate_after_patch`.

[Agent integrations hub](../../docs/AGENT_INTEGRATIONS.md)
