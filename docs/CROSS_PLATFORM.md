# Cross-Platform Guide

TridentChain Security runs on **macOS**, **Linux**, and **Windows** via published packages. You do not need to clone the repository to use the CLI.

| Registry | Package |
|----------|---------|
| PyPI | [tridentchain-security](https://pypi.org/project/tridentchain-security/) |
| npm | [@tridentchain/security-cli](https://www.npmjs.com/package/@tridentchain/security-cli) |

Both install the same command: **`tridentchain-security`**.

---

## Requirements (all platforms)

| Component | Required for | Version |
|-----------|----------------|---------|
| Python | pip package, scanner engine | **3.10+** |
| pip | Installing from PyPI | bundled with Python |
| Node.js | npm wrapper only | **18+** |
| Network | Live advisory sync | optional with `--run-profile offline` |

---

## Install by operating system

### macOS

```bash
python3 -m pip install --upgrade tridentchain-security
npm install -g @tridentchain/security-cli
tridentchain-security --help
```

**Notes**

- Prefer `python3 -m pip` or `pip3` — legacy `/usr/local/bin/pip` may point at a removed system Python (`bad interpreter: /usr/bin/python`).
- CLI is usually installed under `/opt/homebrew/bin` (Apple Silicon) or `/usr/local/bin` (Intel).
- System scan includes **Homebrew** formulae and **macOS applications** (`.app` bundles).

### Linux

```bash
python3 -m pip install --upgrade tridentchain-security
npm install -g @tridentchain/security-cli
tridentchain-security --help
```

**Notes**

- Use your distro’s `python3` and `pip3`, or a virtualenv.
- System scan uses **`dpkg`** (Debian/Ubuntu) or **`rpm`** (RHEL/Fedora) when available.
- VS Code extensions: `~/.vscode/extensions`  
- JetBrains: `~/.local/share/JetBrains` or `~/.config/JetBrains`

### Windows

**PowerShell or Command Prompt:**

```powershell
py -m pip install --upgrade tridentchain-security
npm install -g @tridentchain/security-cli
tridentchain-security --help
```

**Notes**

- Install Python from [python.org](https://www.python.org/downloads/) and enable **“Add Python to PATH”**.
- If `tridentchain-security` is not found, use:

  ```powershell
  py -m scanner.main --help
  ```

  or add `%LocalAppData%\Programs\Python\Python3xx\Scripts` to PATH.

- npm wrapper probes `python`, then `py` on Windows.
- System scan includes Windows applications and developer tools where detectable.

---

## Feature parity by platform

| Capability | macOS | Linux | Windows |
|------------|:-----:|:-----:|:-------:|
| Project dependency scan (`--scan project`) | ✅ | ✅ | ✅ |
| Full scan (`--scan all`) | ✅ | ✅ | ✅ |
| System inventory | ✅ | ✅ | ✅ |
| Homebrew packages | ✅ | — | — |
| macOS `.app` bundles | ✅ | — | — |
| `dpkg` / `rpm` packages | — | ✅ | — |
| Windows apps / tools | — | — | ✅ |
| VS Code extensions | ✅ | ✅ | ✅ |
| JetBrains IDEs / plugins | ✅ | ✅ | ✅ |
| Developer CLIs (node, docker, kubectl, …) | ✅ | ✅ | ✅ |
| HTML + JSON reports | ✅ | ✅ | ✅ |
| No API key (default `full` profile) | ✅ | ✅ | ✅ |

Project and extension scanning behave the same on every OS. System scanning uses OS-specific discovery backends.

---

## Architecture (same on every OS)

```text
┌──────────────────────────────────────────────────────────┐
│  tridentchain-security  (CLI entry point)                │
│  Installed by: pip install tridentchain-security         │
└────────────────────────────┬─────────────────────────────┘
                             │
┌────────────────────────────┴─────────────────────────────┐
│  Optional: @tridentchain/security-cli (npm)              │
│  → finds Python → runs python -m scanner.main            │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│  Scanner engine (Python package `scanner`)                 │
│  • Project manifests (npm, Maven, pip, …)                  │
│  • Advisory sources (OSV, NVD, …)                        │
│  • Reports (JSON / HTML)                                 │
└──────────────────────────────────────────────────────────┘
```

**Important:** The npm package is a launcher only. You must install the PyPI package first:

```bash
pip install tridentchain-security    # required
npm install -g @tridentchain/security-cli   # optional convenience
```

---

## Example commands (all platforms)

```bash
# Help
tridentchain-security --help

# Scan a project directory (any path)
tridentchain-security --scan project --project-path /path/to/repo --output-dir ./out

# Full scan (project + system + extensions)
tridentchain-security --scan all --project-path /path/to/repo --output-dir ./out

# Faster project-only profile
tridentchain-security --scan project --project-path . --run-profile quick --output-dir ./out

# Offline (cached advisories only)
tridentchain-security --scan project --project-path . --run-profile offline --output-dir ./out
```

On Windows, use backslashes or quoted paths, e.g. `--project-path C:\Users\you\project`.

---

## Desktop app (GUI)

The Electron desktop app is **not** published to PyPI/npm. It is optional and uses the same pip-installed engine.

```bash
pip3 install tridentchain-security
cd apps/desktop
npm install
npm run start
```

Works on macOS, Windows, and Linux when Node.js and Electron dependencies install successfully. See [apps/desktop/README.md](../apps/desktop/README.md).

For a fully self-contained installer (bundled Python), see [packaging/README.md](../packaging/README.md).

---

## CI / Docker (Linux)

Typical GitHub Actions or Linux container:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
- run: pip install tridentchain-security
- run: tridentchain-security --scan project --project-path . --output-dir scanner-output
```

---

## Troubleshooting

| Symptom | Platform | Fix |
|---------|----------|-----|
| `pip: bad interpreter` | macOS | Use `python3 -m pip` or `pip3` |
| `tridentchain-security: command not found` | All | Reinstall; add Python `bin`/`Scripts` to PATH |
| npm CLI: package not installed | All | Run `pip install tridentchain-security` first |
| `Python 3.10+ is required` | All | Upgrade Python |
| Slow NVD sync | All | Set `NVD_API_KEY` (optional) |
| GHSA skipped | All | Set `GITHUB_TOKEN` (optional) |
| Permission denied on system paths | Linux | Run without sudo for scans; fix output dir permissions |

---

## Security (all platforms)

- Do **not** commit `.env` or API keys to git.
- Keys are read from environment variables or a local `.env` file only.
- Default scans work **without** API keys.

---

## Related documentation

- [INSTALL_AND_USE.md](INSTALL_AND_USE.md) — step-by-step install
- [AI_INTEGRATION.md](AI_INTEGRATION.md) — agents and automation
- [DISTRIBUTION_VERIFICATION.md](DISTRIBUTION_VERIFICATION.md) — release checklist
- [cli-contract.md](cli-contract.md) — stable CLI flags
