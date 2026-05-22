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

**Agents & MCP (Claude, Cursor, VS Code):**

```bash
pip3 install "tridentchain-security>=0.1.1" tridentchain-mcp
```

What you can do: **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)**  
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

## AI / automation (Claude, OpenAI, Cursor, VS Code, Windsurf, …)

**One install, every agent:** `pip install "tridentchain-security>=0.1.2" tridentchain-mcp`

| Guide | Description |
|-------|-------------|
| **[Agent integrations](docs/AGENT_INTEGRATIONS.md)** | Claude · OpenAI · Cursor · VS Code · Windsurf · Zed · MCP · CLI |
| [Capabilities](docs/CAPABILITIES.md) | Everything you can do today |
| [Architecture](docs/INTEGRATION_ARCHITECTURE.md) | MCP + unified tools design |

```bash
./scripts/setup-agent-mcp.sh cursor   # prints setup for your agent
```

**Phase 2 — Claude MCP:** `pip install tridentchain-mcp` · [Setup guide](docs/CLAUDE_MCP_SETUP.md) · [Plugin](plugins/tridentchain-security/)

**Phase 3 — OpenAI + Cursor:** [examples/openai/](examples/openai/) · [Cursor setup](docs/CURSOR_SETUP.md) · `.cursor/mcp.json.example`

**Phase 4 — VS Code (Anthropic MCP):** Open repo → MCP ready · [VS Code setup](docs/VSCODE_SETUP.md) · `./scripts/vscode-mcp-install-link.sh` · [extension](extensions/vscode-tridentchain/)

**Phase 5 — Validate:** `tridentchain-security --validate` · MCP `validate_after_patch` · [CAPABILITIES.md](docs/CAPABILITIES.md)

Unified tool layer: `from scanner.integrations import execute_tool, get_tool_definitions, to_openai_tools`

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
