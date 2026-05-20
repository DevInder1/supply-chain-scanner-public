# Publishing Guide

## Package names

| Ecosystem | Name | Install command |
|-----------|------|-----------------|
| PyPI | `tridentchain-security` | `pip install tridentchain-security` |
| PyPI | `tridentchain-mcp` | `pip install tridentchain-mcp` (Phase 2; requires `tridentchain-security>=0.1.1`) |
| npm | `@tridentchain/security-cli` | `npm install -g @tridentchain/security-cli` |

CLI command after install: `tridentchain-security` (unchanged)  
MCP server (Phase 2): `tridentchain-mcp`

## One-time setup

### PyPI

1. Create account: https://pypi.org/account/register/
2. Create API token with upload scope
3. Export token:

```bash
export PYPI_TOKEN='pypi-...'
```

### npm

```bash
npm login
```

Create the `@tridentchain` npm organization on the website (required before first publish).  
Step-by-step: [scripts/setup-npm-tridentchain-org.md](../scripts/setup-npm-tridentchain-org.md)

## Build artifacts

```bash
python3 -m pip install --upgrade build twine
python3 -m build
cd tridentchain-mcp && python3 -m build && cd ..
```

npm wrapper:

```bash
cd npm-wrapper
npm pack
```

## Publish

```bash
# PyPI only (recommended for Phase 2 — leaves npm @0.1.0 unchanged)
./scripts/publish-now.sh

# Or with tokens exported:
export PYPI_TOKEN='pypi-...'
./scripts/publish-packages.sh

# npm only when you bump npm-wrapper/package.json version:
PUBLISH_NPM=1 NPM_TOKEN='npm_...' ./scripts/publish-packages.sh
```

Or manually:

```bash
python3 -m twine upload dist/tridentchain_security-*
python3 -m twine upload tridentchain-mcp/dist/tridentchain_mcp-*
cd npm-wrapper && npm publish --access public
```

## Verify

```bash
pip install tridentchain-security
tridentchain-security --help

pip install tridentchain-mcp
python3 -c "from tridentchain_mcp.server import mcp; print(mcp.name)"

npm install -g @tridentchain/security-cli
tridentchain-security --help
```
