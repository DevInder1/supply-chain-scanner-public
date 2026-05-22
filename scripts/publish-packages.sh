#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── 1. Build tools ────────────────────────────────────────────────────────────
echo "Installing build/publish tools..."
python3 -m pip install --upgrade build twine >/dev/null

# ── 2. Read versions from pyproject.toml (single source of truth) ─────────────
SEC_VER=$(python3 -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); print(d['project']['version'])")
MCP_VER=$(python3 -c "import tomllib; d=tomllib.load(open('tridentchain-mcp/pyproject.toml','rb')); print(d['project']['version'])")
echo "Releasing: tridentchain-security==$SEC_VER  tridentchain-mcp==$MCP_VER"

# ── 3. Clean old dist artifacts before building ────────────────────────────────
echo "Cleaning old dist files..."
rm -f dist/tridentchain_security-*.whl dist/tridentchain_security-*.tar.gz
rm -f tridentchain-mcp/dist/tridentchain_mcp-*.whl tridentchain-mcp/dist/tridentchain_mcp-*.tar.gz

# ── 4. Build dist wheels/sdists ───────────────────────────────────────────────
echo "Building tridentchain-security..."
python3 -m build --quiet

echo "Building tridentchain-mcp..."
(cd tridentchain-mcp && python3 -m build --quiet)

# ── 5. Install from the freshly built wheels and smoke-test ───────────────────
echo "Installing local builds for validation..."
python3 -m pip install --force-reinstall --quiet \
  "dist/tridentchain_security-${SEC_VER}-py3-none-any.whl" \
  "tridentchain-mcp/dist/tridentchain_mcp-${MCP_VER}-py3-none-any.whl"

echo "Smoke-testing imports..."
python3 - <<'PY'
from tridentchain_mcp.server import mcp, __version__ as _ver_mod
from tridentchain_mcp import __version__ as _ver_init
assert mcp.name == "tridentchain-security", f"unexpected mcp.name: {mcp.name}"
assert _ver_mod == _ver_init, f"version mismatch: server={_ver_mod} __init__={_ver_init}"
print(f"  OK: tridentchain-mcp {_ver_init}")
PY

python3 - <<'PY'
from scanner.integrations import execute_tool
result = execute_tool("scan_project", {"project_path": ".", "max_findings": 1})
assert result.get("status") == "ok", f"unexpected status: {result}"
print("  OK: scanner integration")
PY

# ── 4. PyPI upload ────────────────────────────────────────────────────────────
if [[ -z "${PYPI_TOKEN:-}" ]]; then
  echo "ERROR: PYPI_TOKEN is not set."
  exit 1
fi

echo "Publishing tridentchain-security to PyPI..."
python3 -m twine upload --skip-existing dist/tridentchain_security-* -u __token__ -p "$PYPI_TOKEN"

echo "Publishing tridentchain-mcp to PyPI..."
python3 -m twine upload --skip-existing tridentchain-mcp/dist/tridentchain_mcp-* -u __token__ -p "$PYPI_TOKEN"

# ── 5. npm (opt-in) ───────────────────────────────────────────────────────────
if [[ "${PUBLISH_NPM:-0}" == "1" ]]; then
  echo "Publishing npm wrapper..."
  if [[ -z "${NPM_TOKEN:-}" ]]; then
    echo "ERROR: NPM_TOKEN is not set (use an npm automation/granular token with publish access)."
    exit 1
  fi
  NODE_AUTH_TOKEN="$NPM_TOKEN" npm publish --access public --prefix npm-wrapper
else
  echo "Skipping npm publish (set PUBLISH_NPM=1 to release @tridentchain/security-cli)."
fi

echo "Done."
