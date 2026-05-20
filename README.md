# TridentChain Security

Local-first vulnerability scanner for project dependencies, developer tools, and IDE extensions.  
Uses multi-source intelligence (OSV, NVD, GHSA, Sonatype) with KEV/EPSS prioritization.

**No API key required** for default usage.

Public repo: https://github.com/DevInder1/supply-chain-scanner-public

---

## Install (plug and play)

```bash
pip3 install tridentchain-security
npm install -g @tridentchain/security-cli
tridentchain-security --help
```

Full guide: **[docs/INSTALL_AND_USE.md](docs/INSTALL_AND_USE.md)**  
Cross-platform (macOS / Linux / Windows): **[docs/CROSS_PLATFORM.md](docs/CROSS_PLATFORM.md)**  
(PyPI: [tridentchain-security](https://pypi.org/project/tridentchain-security/) · npm: [@tridentchain/security-cli](https://www.npmjs.com/package/@tridentchain/security-cli))

```bash
tridentchain-security --scan all --project-path . --output-dir scanner-output
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

## Desktop app (individual application)

No repo clone required if the pip package is installed:

```bash
pip3 install tridentchain-security
cd apps/desktop && npm install && npm run start
```

See [apps/desktop/README.md](apps/desktop/README.md) and [docs/DISTRIBUTION_VERIFICATION.md](docs/DISTRIBUTION_VERIFICATION.md).

## AI / automation

Use CLI JSON or `run_scan()` from any agent — [docs/AI_INTEGRATION.md](docs/AI_INTEGRATION.md).

**Integration architecture** (Claude MCP, OpenAI, Cursor, VS Code): [docs/INTEGRATION_ARCHITECTURE.md](docs/INTEGRATION_ARCHITECTURE.md) · [Roadmap](docs/ROADMAP_INTEGRATIONS.md)

**Phase 2 — Claude MCP:** `pip install tridentchain-mcp` · [Setup guide](docs/CLAUDE_MCP_SETUP.md) · [Plugin](plugins/tridentchain-security/)

Unified tool layer: `from scanner.integrations import execute_tool, get_tool_definitions`

---

## Development

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
python3 -m pip install -e .
tridentchain-security --help
python3 -m unittest scanner.tests.test_matcher_ranges -v
```

Install & use: `docs/INSTALL_AND_USE.md`  
Cross-platform: `docs/CROSS_PLATFORM.md`  
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
