# Zed + TridentChain MCP

1. `pip install "tridentchain-security>=0.1.2" tridentchain-mcp`
2. Open Zed → **Settings** → merge [settings.mcp.json.example](settings.mcp.json.example) into `~/.config/zed/settings.json` under `context_servers` (Zed MCP layout may vary by version — check Zed docs for **Model Context Protocol**).
3. Restart Zed and enable the **tridentchain** context server in the assistant panel.

Fallback: terminal → `tridentchain-security --scan project --project-path . --output-dir .tridentchain-out`

[Agent integrations hub](../../docs/AGENT_INTEGRATIONS.md)
