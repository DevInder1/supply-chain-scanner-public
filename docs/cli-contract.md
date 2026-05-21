# Scanner CLI Contract

This document defines the stable command contract used by the desktop app.

## Entry Point

- `python -m scanner.main`

## Stable Flags

- `--scan all|system|project`
- `--run-profile quick|full|offline`
- `--project-path <path>`
- `--config <path>`
- `--db-path <path>`
- `--output-dir <path>` (preferred for desktop app)
- `--output <path>`
- `--html <path>`
- `--vuln-html <path>`
- `--offline`
- `--nvd-api-key <key>`
- `--github-token <token>`
- `--validate` (≥0.1.1) — compare two reports; no scan
- `--baseline-report <path>` — baseline JSON (with `--validate`)
- `--after-report <path>` — after-patch JSON (with `--validate`)

## Validate Mode (Phase 5)

When `--validate` is set, the CLI does **not** run a scan. It loads two JSON files and prints a diff payload:

```bash
tridentchain-security --validate \
  --baseline-report .tridentchain-out/baseline.json \
  --after-report .tridentchain-out/scan-report.json
```

Accepted inputs: stdout summary JSON (`affected_components`) or full `scan-report.json` (`vulnerabilities`).

## Run Profile Semantics

- `quick`: scan only project dependencies unless `--scan` is explicitly set.
- `full`: preserve provided scan settings.
- `offline`: enforce offline mode and use local cache only.

## Deterministic Output Files

When `--output-dir` is supplied, report paths are deterministic:

- JSON: `scan-report.json`
- HTML summary: `scan-report.html`
- HTML vulnerabilities: `scan-vulnerabilities.html`

## Summary JSON Printed To Stdout

The command always prints a final JSON summary payload including:

- `summary`
- `components_scanned`
- `osv_queryable`
- `osv_unqueryable`
- `intelligence_sources`
- `affected_components`
- `report_path`
- `run_profile`
- `output_paths`

Desktop integrations should parse this stdout JSON to discover generated files.
