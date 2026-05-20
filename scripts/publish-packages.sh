#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Building Python packages..."
python3 -m pip install --upgrade build twine >/dev/null
python3 -m build
(cd tridentchain-mcp && python3 -m build)

if [[ -z "${PYPI_TOKEN:-}" ]]; then
  echo "ERROR: PYPI_TOKEN is not set."
  exit 1
fi
echo "Publishing tridentchain-security to PyPI..."
python3 -m twine upload --skip-existing dist/tridentchain_security-* -u __token__ -p "$PYPI_TOKEN"
echo "Publishing tridentchain-mcp to PyPI..."
python3 -m twine upload --skip-existing tridentchain-mcp/dist/tridentchain_mcp-* -u __token__ -p "$PYPI_TOKEN"

# npm is opt-in so existing @tridentchain/security-cli@0.1.0 stays untouched.
if [[ "${PUBLISH_NPM:-0}" == "1" ]]; then
  echo "Publishing npm wrapper..."
  cd npm-wrapper
  if [[ -z "${NPM_TOKEN:-}" ]]; then
    echo "ERROR: NPM_TOKEN is not set (use an npm automation/granular token with publish access)."
    exit 1
  fi
  NODE_AUTH_TOKEN="$NPM_TOKEN" npm publish --access public
else
  echo "Skipping npm publish (set PUBLISH_NPM=1 to release @tridentchain/security-cli)."
fi

echo "Done."
