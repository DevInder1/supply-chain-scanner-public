#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Building Python package..."
python3 -m pip install --upgrade build twine >/dev/null
python3 -m build

if [[ -z "${PYPI_TOKEN:-}" ]]; then
  echo "ERROR: PYPI_TOKEN is not set."
  exit 1
fi
echo "Publishing to PyPI..."
python3 -m twine upload dist/* -u __token__ -p "$PYPI_TOKEN"

echo "Publishing npm wrapper..."
cd npm-wrapper
if [[ -z "${NPM_TOKEN:-}" ]]; then
  echo "ERROR: NPM_TOKEN is not set (use an npm automation/granular token with publish access)."
  exit 1
fi
NODE_AUTH_TOKEN="$NPM_TOKEN" npm publish --access public

echo "Done."
