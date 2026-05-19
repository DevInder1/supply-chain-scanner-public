# Supply Chain Scanner

Local-first vulnerability scanner for project dependencies, developer tools, and IDE extensions.  
Uses multi-source intelligence (OSV, NVD, GHSA, Sonatype) with KEV/EPSS prioritization.

**No API key required** for default usage.

Public repo: https://github.com/DevInder1/supply-chain-scanner-public

---

## Install (plug and play)

### Python (recommended)

```bash
pip install devinder-supply-chain-scanner
```

```bash
supply-chain-scanner --scan all --project-path . --output-dir scanner-output
```

### npm (Node wrapper)

Requires Python 3.10+ and the pip package above.

```bash
npm install -g @devinder1/supply-chain-scanner-cli
```

```bash
supply-chain-scanner --scan project --project-path .
```

---

## Use in your own Python app

```python
from scanner import run_scan

summary = run_scan(
    project_path=".",
    scan="all",
    run_profile="full",  # no API key required
    output_dir="scanner-output",
)
print(summary["summary"])
```

---

## Scan profiles

| Profile | Description |
|---------|-------------|
| `full` (default) | Project + system + extensions. OSV + NVD without keys. |
| `quick` | Faster project-focused scan. |
| `offline` | Local advisory DB only, no network. |
| Power-user | Add `GITHUB_TOKEN`, `NVD_API_KEY`, optional `SONATYPE_TOKEN` for best coverage. |

---

## Desktop app

```bash
cd apps/desktop
npm install
npm run start
```

---

## Development

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
python3 -m pip install -e .
supply-chain-scanner --help
python3 -m unittest scanner.tests.test_matcher_ranges -v
```

CLI contract: `docs/cli-contract.md`  
Publishing: `docs/PUBLISHING.md`

---

## Optional API keys (power users)

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Higher NVD rate limits |
| `GITHUB_TOKEN` | GHSA advisories |
| `SONATYPE_TOKEN` | Sonatype Guide advisories |

Set in `.env` or environment variables.

---

## License

MIT — see [LICENSE](LICENSE)
