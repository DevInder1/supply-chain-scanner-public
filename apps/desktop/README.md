# TridentChain Security Desktop

Electron UI for TridentChain Security — run scans without using the terminal.

## Two ways to run (no full repo clone required)

### A) End user (recommended)

Install the published scanner, then run only the desktop app:

```bash
pip3 install tridentchain-security
cd apps/desktop
npm install
npm run start
```

The app uses `tridentchain-security` from your PATH. Pick any project folder to scan.

### B) Developer (monorepo)

```bash
git clone https://github.com/DevInder1/supply-chain-scanner-public.git
cd supply-chain-scanner-public
pip3 install -e .
cd apps/desktop && npm install && npm run start
```

## Features

- Scan profiles: Recommended (public), Quick, Power-user, Offline
- Live log streaming and HTML/JSON report links
- Optional API keys via environment (never stored in the UI)

## API keys

Set locally (not in the app UI):

- `NVD_API_KEY`
- `GITHUB_TOKEN`
- `SONATYPE_TOKEN` (optional)

Or place them in a `.env` file next to the app executable (packaged) or in your home directory.

## Build installer (optional)

```bash
python3 packaging/scripts/bundle_scanner_runtime.py --target macos
cd apps/desktop && npm run dist
```

See [packaging/README.md](../../packaging/README.md).

## AI integration

Agents can use the same engine via CLI or Python API without this desktop app. See [docs/AI_INTEGRATION.md](../../docs/AI_INTEGRATION.md).
