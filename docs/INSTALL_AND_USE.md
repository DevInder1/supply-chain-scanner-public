# TridentChain Security — Install & Use

This guide explains how to install TridentChain Security from **PyPI** and **npm**, verify the CLI, and run your first scan.

**Published packages**

| Registry | Package | Install |
|----------|---------|---------|
| PyPI | [tridentchain-security](https://pypi.org/project/tridentchain-security/) | `pip3 install tridentchain-security` |
| npm | [@tridentchain/security-cli](https://www.npmjs.com/package/@tridentchain/security-cli) | `npm install -g @tridentchain/security-cli` |

After install, both paths expose the same command: **`tridentchain-security`**.

---

## Prerequisites

- **Python 3.10+** (required for the scanner engine)
- **Node.js 18+** (only if you install the npm wrapper)
- macOS / Linux / Windows

On macOS with Homebrew Python, prefer `pip3` or `python3 -m pip` instead of a broken legacy `pip` shim.

**Platform-specific install commands:** see [CROSS_PLATFORM.md](CROSS_PLATFORM.md).

---

## Step 1 — Install the Python package (core)

```bash
pip3 install tridentchain-security
```

**What this does**

- Downloads the scanner from PyPI.
- Installs the `scanner` Python module and dependencies (`requests`, `defusedxml`).
- Registers the CLI entry point **`tridentchain-security`** on your PATH.

**Alternative (recommended on macOS)**

```bash
python3 -m pip install tridentchain-security
```

**If you see** `bad interpreter: /usr/bin/python`

Your `pip` command points at a removed system Python. Use `pip3` or `python3 -m pip` as above.

### Agents, MCP, and validate (recommended ≥0.1.1)

For Claude, Cursor, VS Code, OpenAI tools, and **validate-after-patch**:

```bash
pip3 install "tridentchain-security>=0.1.1"
pip3 install tridentchain-mcp
```

| Package | Purpose |
|---------|---------|
| `tridentchain-security>=0.1.1` | Unified tools (`scanner.integrations`), `--validate` CLI |
| `tridentchain-mcp` | Local stdio MCP (`scan_project`, `scan_full`, `validate_after_patch`) |

**Legacy pin still works:** `pip3 install tridentchain-security==0.1.0` — scan commands only, no MCP integrations.

Full capability list: **[CAPABILITIES.md](CAPABILITIES.md)**.

---

## Step 2 — Install the npm wrapper (optional)

```bash
npm install -g @tridentchain/security-cli
```

**What this does**

- Installs a small Node.js launcher globally.
- The launcher checks that the Python package is installed, then runs `python3 -m scanner.main` with your CLI arguments.
- Exposes the same command: **`tridentchain-security`**.

**You need both** if you use the npm path: the npm package is a wrapper; the Python package does the actual scanning.

---

## Step 3 — Verify installation

```bash
tridentchain-security --help
```

You should see usage for `--scan`, `--run-profile`, `--project-path`, `--output-dir`, and (≥0.1.1) `--validate`.

Quick version check:

```bash
python3 -c "import scanner; print(scanner.__version__)"
```

---

## How it works (architecture)

```text
┌─────────────────────────────────────────────────────────────┐
│  tridentchain-security  (CLI command)                       │
└───────────────────────────┬─────────────────────────────────┘
                            │
         ┌──────────────────┴──────────────────┐
         │                                     │
   pip install                          npm install -g
   tridentchain-security                 @tridentchain/security-cli
         │                                     │
         ▼                                     ▼
   Python entry point                   Node wrapper script
   scanner.main:main                   → python3 -m scanner.main
         │                                     │
         └──────────────────┬──────────────────┘
                            ▼
              ┌─────────────────────────────┐
              │  Scanner engine (Python)    │
              │  • Discover manifests       │
              │  • Sync advisories (OSV…)   │
              │  • Match CVEs / GHSA / KEV  │
              │  • Generate HTML/JSON       │
              └─────────────────────────────┘
```

1. **Discovery** — Finds dependencies from `package.json`, lockfiles, `requirements.txt`, system tools, VS Code / JetBrains extensions, etc.
2. **Intelligence** — Pulls vulnerability data from public sources (OSV, NVD, and more). No API key required for default `full` profile.
3. **Matching** — Compares installed versions against affected version ranges.
4. **Reports** — Writes JSON and HTML reports to your chosen output directory.

---

## First scan

### Recommended (project + system + extensions)

```bash
cd /path/to/your/project
tridentchain-security --scan all --project-path . --output-dir scanner-output
```

### Project dependencies only (faster)

```bash
tridentchain-security --scan project --project-path . --output-dir scanner-output
```

### Quick profile (lighter run)

```bash
tridentchain-security --scan all --project-path . --run-profile quick --output-dir scanner-output
```

### Offline (cached data only)

```bash
tridentchain-security --scan project --project-path . --run-profile offline --output-dir scanner-output
```

### Validate after dependency upgrades (≥0.1.1)

```bash
cp scanner-output/scan-report.json scanner-output/baseline.json
# upgrade dependencies, then scan again into scanner-output/
tridentchain-security --validate \
  --baseline-report scanner-output/baseline.json \
  --after-report scanner-output/scan-report.json
```

Or use MCP tool `validate_after_patch` via `tridentchain-mcp`. See [CAPABILITIES.md](CAPABILITIES.md).

---

## Scan profiles

| Profile | Flag | Behavior |
|---------|------|----------|
| **full** | `--run-profile full` (default) | Project + system + extensions; OSV + NVD without keys |
| **quick** | `--run-profile quick` | Faster, project-focused |
| **offline** | `--run-profile offline` | Local advisory cache only, no network |

---

## Output files

With `--output-dir scanner-output`, typical outputs include:

| File | Description |
|------|-------------|
| `scan-report.json` | Machine-readable summary |
| `scan-report.html` | Main HTML dashboard |
| `scan-vulnerabilities.html` | Vulnerabilities and fix versions |
| `scan-remediation-epss.html` | EPSS-prioritized remediation view |

Open the HTML files in any browser.

---

## Optional API keys (power users)

Set environment variables or pass flags for richer coverage:

| Variable / flag | Purpose |
|-----------------|--------|
| `NVD_API_KEY` / `--nvd-api-key` | Higher NVD rate limits |
| `GITHUB_TOKEN` / `--github-token` | GitHub Security Advisory (GHSA) data |
| `SONATYPE_TOKEN` | Sonatype Guide advisories |

Example:

```bash
export GITHUB_TOKEN=ghp_...
export NVD_API_KEY=...
tridentchain-security --scan all --project-path . --output-dir scanner-output
```

---

## Use from Python code

```python
from scanner import run_scan

summary = run_scan(
    project_path=".",
    scan="all",
    run_profile="full",
    output_dir="scanner-output",
)
print(summary["summary"])
```

---

## Uninstall

```bash
pip3 uninstall tridentchain-security
npm uninstall -g @tridentchain/security-cli
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `pip: bad interpreter` | Use `pip3 install` or `python3 -m pip install` |
| `command not found: tridentchain-security` | Ensure Python/ npm global bin is on your `PATH` |
| npm wrapper: package not installed | Run `pip3 install tridentchain-security` first |
| Slow first run | First sync downloads advisory data; later runs use cache |

---

## Optional: Claude / MCP (Phase 2)

The pip CLI above is unchanged. For Claude Desktop, Claude Code, or Cursor MCP:

```bash
pip3 install "tridentchain-security>=0.1.1"
pip3 install tridentchain-mcp
```

See [CLAUDE_MCP_SETUP.md](CLAUDE_MCP_SETUP.md).

## Optional: Cursor / OpenAI (Phase 3)

- Cursor: [CURSOR_SETUP.md](CURSOR_SETUP.md) (MCP + `.cursor/rules/tridentchain.mdc`)
- OpenAI: [examples/openai/](../examples/openai/)
- VS Code: [VSCODE_SETUP.md](VSCODE_SETUP.md) (extension + MCP)

---

## Related docs

- [CAPABILITIES.md](CAPABILITIES.md) — everything you can do with CLI, MCP, and agents
- [README](../README.md) — project overview
- [Cross-platform](CROSS_PLATFORM.md) — macOS, Linux, Windows install and parity
- [Claude MCP setup](CLAUDE_MCP_SETUP.md) — Phase 2 MCP + plugin
- [Cursor setup](CURSOR_SETUP.md) — Phase 3 MCP + rules
- [VS Code setup](VSCODE_SETUP.md) — Phase 4 extension (MCP-first)
- [Publishing](PUBLISHING.md) — maintainers: PyPI/npm release
- [CLI contract](cli-contract.md) — stable CLI flags for integrations
