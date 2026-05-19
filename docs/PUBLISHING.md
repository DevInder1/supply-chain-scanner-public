# Publishing Guide

## Package names

| Ecosystem | Name | Install command |
|-----------|------|-----------------|
| PyPI | `devinder-supply-chain-scanner` | `pip install devinder-supply-chain-scanner` |
| npm | `@devinder1/supply-chain-scanner-cli` | `npm install -g @devinder1/supply-chain-scanner-cli` |

CLI command after install: `supply-chain-scanner`

> Note: `supply-chain-scanner` on PyPI is already used by another project, so this repo publishes under `devinder-supply-chain-scanner`.

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

## Build artifacts

```bash
python3 -m pip install --upgrade build twine
python3 -m build
```

npm wrapper:

```bash
cd npm-wrapper
npm pack
```

## Publish

```bash
./scripts/publish-packages.sh
```

Or manually:

```bash
python3 -m twine upload dist/*
cd npm-wrapper && npm publish --access public
```

## Verify

```bash
pip install devinder-supply-chain-scanner
supply-chain-scanner --help

npm install -g @devinder1/supply-chain-scanner-cli
supply-chain-scanner --help
```
