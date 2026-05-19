# Publishing Guide

## Package names

| Ecosystem | Name | Install command |
|-----------|------|-----------------|
| PyPI | `tridentchain-security` | `pip install tridentchain-security` |
| npm | `@tridentchain/security-cli` | `npm install -g @tridentchain/security-cli` |

CLI command after install: `tridentchain-security`

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
pip install tridentchain-security
tridentchain-security --help

npm install -g @tridentchain/security-cli
tridentchain-security --help
```
