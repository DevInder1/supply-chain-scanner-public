#!/usr/bin/env bash
# Load tokens from .publish-secrets (gitignored) then publish both packages.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_FILE="$ROOT/.publish-secrets"

if [[ -f "$SECRETS_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$SECRETS_FILE"
  set +a
fi

if [[ -z "${PYPI_TOKEN:-}" ]]; then
  echo "Missing PYPI_TOKEN."
  echo "Create $SECRETS_FILE with:"
  echo '  PYPI_TOKEN=pypi-...'
  exit 1
fi

# Default: PyPI only (0.1.1 + tridentchain-mcp). npm stays at 0.1.0 unless PUBLISH_NPM=1.
export PYPI_TOKEN
export PUBLISH_NPM="${PUBLISH_NPM:-0}"
if [[ "$PUBLISH_NPM" == "1" ]]; then
  if [[ -z "${NPM_TOKEN:-}" ]]; then
    echo "PUBLISH_NPM=1 requires NPM_TOKEN in $SECRETS_FILE"
    exit 1
  fi
  export NPM_TOKEN
fi

"$ROOT/scripts/publish-packages.sh"

# Optional: store in GitHub Actions for CI publishes
if command -v gh >/dev/null 2>&1; then
  echo "$PYPI_TOKEN" | gh secret set PYPI_TOKEN -R DevInder1/supply-chain-scanner-public --body -
  echo "$NPM_TOKEN" | gh secret set NPM_TOKEN -R DevInder1/supply-chain-scanner-public --body -
  echo "GitHub secrets PYPI_TOKEN and NPM_TOKEN updated."
fi
