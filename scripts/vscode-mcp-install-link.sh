#!/usr/bin/env bash
# Print VS Code one-click MCP install link for TridentChain.
set -euo pipefail
python3 - <<'PY'
import json
import urllib.parse

cfg = {
    "name": "tridentchain",
    "type": "stdio",
    "command": "python3",
    "args": ["-m", "tridentchain_mcp"],
}
link = "vscode:mcp/install?" + urllib.parse.quote(json.dumps(cfg))
print("TridentChain MCP — VS Code one-click install link:\n")
print(link)
print("\nOpen in browser or: open '" + link + "'  # macOS")
PY
