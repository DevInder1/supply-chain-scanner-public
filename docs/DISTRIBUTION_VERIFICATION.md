# TridentChain Security — Distribution Verification

This document verifies both distribution paths: **standalone desktop app** and **published packages** (PyPI + npm).

Last verified: 2026-05-19

---

## 1) Package distribution (wide reach, no clone)

| Check | Status | Notes |
|-------|--------|-------|
| PyPI package live | ✅ | [tridentchain-security 0.1.0](https://pypi.org/project/tridentchain-security/0.1.0/) |
| npm wrapper live | ✅ | [@tridentchain/security-cli 0.1.0](https://www.npmjs.com/package/@tridentchain/security-cli) |
| CLI command | ✅ | `tridentchain-security` |
| Install docs | ✅ | [INSTALL_AND_USE.md](INSTALL_AND_USE.md) |
| Python API | ✅ | `from scanner import run_scan` |
| No keys required (default) | ✅ | OSV + NVD work without tokens |
| Secrets in repo | ✅ | `.env`, `.publish-secrets` gitignored; only placeholders in `config.yaml` |

### Install anywhere (no git clone)

```bash
pip3 install tridentchain-security
npm install -g @tridentchain/security-cli
tridentchain-security --help
```

### Example scan

```bash
tridentchain-security --scan all --project-path /path/to/project --output-dir ./scanner-output
```

---

## 2) Individual desktop application

| Check | Status | Notes |
|-------|--------|-------|
| Electron UI | ✅ | `apps/desktop` — TridentChain Security |
| Security (sandbox, CSP, no node in renderer) | ✅ | `contextIsolation`, path allowlist for reports |
| API keys in UI | ✅ | None stored; env / `.env` only |
| Uses pip CLI when no repo | ✅ | Prefers `tridentchain-security` on PATH |
| Dev mode (repo) | ✅ | `python3 -m scanner.main` from monorepo |
| Packaged zero-install build | ⚠️ | Requires `packaging/scripts/bundle_scanner_runtime.py` before `npm run dist` |

### Run desktop without cloning (recommended)

1. Install scanner once:

   ```bash
   pip3 install tridentchain-security
   ```

2. Install desktop deps and start:

   ```bash
   cd apps/desktop
   npm install
   npm run start
   ```

3. Pick any project folder in the UI — no monorepo required.

### Run from full repo (developers)

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
pip3 install -e .
cd apps/desktop && npm install && npm run start
```

### Ship as `.dmg` / installer (optional)

```bash
python3 packaging/scripts/bundle_scanner_runtime.py --target macos
cd apps/desktop && npm run dist
```

See [packaging/README.md](../packaging/README.md).

---

## 3) Security — API keys and secrets

| Item | Status |
|------|--------|
| `.env` in `.gitignore` | ✅ |
| `.publish-secrets` in `.gitignore` | ✅ |
| `.vscode/` (local IDE settings) | ✅ gitignored |
| Hardcoded tokens in source | ✅ None (only commented placeholders) |
| Keys via environment | ✅ `NVD_API_KEY`, `GITHUB_TOKEN`, `SONATYPE_TOKEN` |
| Desktop loads `.env` safely | ✅ Does not override existing env vars |
| Publish tokens | ✅ GitHub Actions secrets only (not in repo) |

**Never commit:** `.env`, `.publish-secrets`, npm/PyPI tokens, or real keys in `config.yaml`.

---

## 4) AI / automation integration (no clone)

TridentChain Security is designed for tools that run local commands or embed Python:

| Method | Use case |
|--------|----------|
| **CLI JSON** | Agents run `tridentchain-security ...` and parse trailing JSON |
| **Python API** | `run_scan()` returns the same summary dict |
| **Desktop** | Human-friendly UI; same engine underneath |

See [AI_INTEGRATION.md](AI_INTEGRATION.md).

---

## 5) Source integrity

| Component | Location | Published? |
|-----------|----------|------------|
| Scanner engine | `scanner/` | ✅ PyPI package |
| CLI entry | `scanner/main.py` | ✅ `tridentchain-security` |
| Public API | `scanner/api.py` | ✅ |
| npm wrapper | `npm-wrapper/` | ✅ npm |
| Desktop shell | `apps/desktop/` | GitHub only (not on npm/PyPI) |
| Reports | `scanner/reports/` | ✅ in PyPI wheel |

---

## 6) Known gaps / next improvements

1. **Desktop installer** — bundle full Python + deps for true offline installer (see `packaging/`).
2. **PyPI README** — bump to 0.1.1 to refresh PyPI page with latest install doc.
3. **VS Code extension** — optional future distribution channel.
4. **CI publish** — GitHub Actions workflow exists; secrets configured.

---

## Quick verification commands

```bash
# Packages
pip3 show tridentchain-security
npm view @tridentchain/security-cli version

# CLI
tridentchain-security --help
python3 -m unittest scanner.tests.test_matcher_ranges -v

# No secrets in git
git check-ignore -v .env .publish-secrets
```
