#!/usr/bin/env bash
# Validate TridentChain Claude plugin before Anthropic submission.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN="$ROOT/plugins/tridentchain-security"
FAIL=0

ok() { echo "  OK: $1"; }
fail() { echo "  FAIL: $1"; FAIL=1; }

echo "=== TridentChain plugin validation ==="

# Required files
for f in \
  "$PLUGIN/.claude-plugin/plugin.json" \
  "$PLUGIN/.mcp.json" \
  "$PLUGIN/PRIVACY.md" \
  "$PLUGIN/SECURITY.md" \
  "$PLUGIN/README.md" \
  "$PLUGIN/skills/supply-chain-scan/SKILL.md" \
  "$PLUGIN/skills/validate-fixes/SKILL.md"; do
  [[ -f "$f" ]] && ok "$(basename "$f")" || fail "missing $f"
done

# plugin.json fields
python3 - <<'PY' "$PLUGIN/.claude-plugin/plugin.json" || exit 1
import json, sys
p = json.load(open(sys.argv[1]))
required = ["name", "version", "description", "author"]
for k in required:
    assert k in p and p[k], f"missing plugin.json: {k}"
assert p["name"] == "tridentchain-security"
privacy = p.get("privacy_policies") or []
assert privacy and privacy[0].startswith("https://"), "privacy_policies HTTPS URL required"
print("  OK: plugin.json schema")
PY

# MCP tools have annotations
python3 - <<PY
import pathlib
text = pathlib.Path("$ROOT/tridentchain-mcp/src/tridentchain_mcp/server.py").read_text()
for tool in ("scan_project", "scan_full", "validate_after_patch"):
    assert f"def {tool}" in text, tool
assert "readOnlyHint" in text and "title" in text
print("  OK: MCP tool annotations present")
PY

# PyPI packages
if python3 -c "from tridentchain_mcp.server import mcp" 2>/dev/null; then
  ok "tridentchain-mcp import"
else
  fail "pip install tridentchain-security tridentchain-mcp"
fi

if command -v tridentchain-security >/dev/null 2>&1; then
  ok "tridentchain-security on PATH"
else
  fail "tridentchain-security not on PATH"
fi

# Claude CLI validate (optional)
if command -v claude >/dev/null 2>&1; then
  if claude plugin validate "$PLUGIN" 2>/dev/null; then
    ok "claude plugin validate"
  else
    echo "  WARN: claude plugin validate failed or unavailable — run manually"
  fi
else
  echo "  SKIP: claude CLI not installed"
fi

echo ""
if [[ "$FAIL" -eq 0 ]]; then
  echo "All required checks passed."
  echo "Next: docs/PLUGIN_SUBMISSION.md · SUBMISSION_CHECKLIST.md"
  exit 0
fi
echo "Some checks failed."
exit 1
