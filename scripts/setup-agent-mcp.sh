#!/usr/bin/env bash
# Print TridentChain setup steps for Claude, Cursor, VS Code, Windsurf, OpenAI, or generic MCP.
set -euo pipefail

AGENT="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MCP_BLOCK='{
  "tridentchain": {
    "command": "python3",
    "args": ["-m", "tridentchain_mcp"]
  }
}'

echo "TridentChain — agent setup helper"
echo "Install: pip install \"tridentchain-security>=0.1.2\" tridentchain-mcp"
echo ""

AGENT_LC="$(echo "$AGENT" | tr '[:upper:]' '[:lower:]')"
case "$AGENT_LC" in
  claude|claude-desktop)
    echo "=== Claude Desktop ==="
    echo "File (macOS): ~/Library/Application Support/Claude/claude_desktop_config.json"
    echo 'Add under "mcpServers":'
    echo "$MCP_BLOCK"
    echo "Doc: $ROOT/docs/CLAUDE_MCP_SETUP.md"
    ;;
  claude-code|plugin)
    echo "=== Claude Code (plugin) ==="
    echo "  claude --plugin-dir $ROOT/plugins/tridentchain-security"
    echo "Doc: $ROOT/docs/CLAUDE_MCP_SETUP.md"
    ;;
  cursor)
    echo "=== Cursor ==="
    echo "  cp $ROOT/.cursor/mcp.json.example .cursor/mcp.json"
    echo "  Enable rule: .cursor/rules/tridentchain.mdc"
    echo "Doc: $ROOT/docs/CURSOR_SETUP.md"
    ;;
  vscode|code)
    echo "=== VS Code ==="
    echo "  Open repo (includes .vscode/mcp.json) OR:"
    echo "  $ROOT/scripts/vscode-mcp-install-link.sh"
    echo "Doc: $ROOT/docs/VSCODE_SETUP.md"
    ;;
  windsurf)
    echo "=== Windsurf ==="
    echo "  Merge: $ROOT/integrations/windsurf/mcp_config.json.example"
    echo "  Into: ~/.codeium/windsurf/mcp_config.json"
    echo "  Then restart Windsurf."
    echo "Doc: $ROOT/integrations/windsurf/README.md"
    ;;
  zed)
    echo "=== Zed ==="
    echo "  See: $ROOT/integrations/zed/README.md"
    ;;
  openai|gpt)
    echo "=== OpenAI ==="
    echo "  pip install openai"
    echo "  Examples: $ROOT/examples/openai/"
    echo "  Doc: $ROOT/integrations/openai/README.md"
    ;;
  mcp|generic|"")
    echo "=== Generic MCP (mcpServers) ==="
    cat "$ROOT/integrations/mcp/mcpServers.json"
    echo "Doc: $ROOT/docs/AGENT_INTEGRATIONS.md"
    ;;
  *)
    echo "Unknown agent: $AGENT"
    echo "Usage: $0 [claude|cursor|vscode|windsurf|zed|openai|mcp]"
    exit 1
    ;;
esac

echo ""
echo "Agent prompt snippet: $ROOT/integrations/AGENT_PROMPT.txt"
echo "Full matrix: $ROOT/docs/AGENT_INTEGRATIONS.md"
