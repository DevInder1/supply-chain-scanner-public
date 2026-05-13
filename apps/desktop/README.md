# Desktop App (Electron)

This app wraps the scanner CLI with:

- command builder
- one-click scan execution
- live log streaming
- JSON/HTML result access

## Local Development

From `apps/desktop`:

1. `npm install`
2. `npm run start`

The app runs the scanner from repo root using:

- `python -m scanner.main ...`

In packaged builds, a bundled Python runtime is preferred automatically.

## API keys (no UI entry required)

Do not paste secrets in the app. Keep keys locally via environment variables:

- `NVD_API_KEY`
- `GITHUB_TOKEN`
- `SONATYPE_TOKEN` (optional)

You can also place them in a repo-root `.env` file. The scanner reads `.env` automatically.
