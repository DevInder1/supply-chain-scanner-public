# @devinder1/supply-chain-scanner-cli

Node.js wrapper for the Python Supply Chain Scanner.

## Install

```bash
pip install devinder-supply-chain-scanner
npm install -g @devinder1/supply-chain-scanner-cli
```

## Usage

```bash
supply-chain-scanner --scan all --project-path . --output-dir scanner-output
```

Forwards all arguments to `python -m scanner.main`.
