#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Building Python package..."
python3 -m pip install --upgrade build twine >/dev/null
python3 -m build

if [[ -z "${PYPI_TOKEN:-}" ]]; then
  echo "PYPI_TOKEN is not set. Skipping PyPI upload."
  echo "Set PYPI_TOKEN and rerun to publish to PyPI."
else
  echo "Publishing to PyPI..."
  python3 -m twine upload dist/*
fi

echo "Publishing npm wrapper..."
cd npm-wrapper
if npm whoami >/dev/null 2>&1; then
  npm publish --access public
else
  echo "npm is not authenticated. Run 'npm login' and retry."
  exit 1
fi

echo "Done."
