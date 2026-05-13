# Supply Chain Scanner

Local-first vulnerability scanner with a desktop command-builder workflow.

## Scanner CLI

- Entry point: `python -m scanner.main`
- CLI contract: `docs/cli-contract.md`

## Desktop App

- Path: `apps/desktop`
- Start: `npm install && npm run start`
- Works without API keys by default; optional keys only improve coverage/rate limits

## No-Key Usage (Public Friendly)

- Recommended public setup:
  - Default mode: no key required
  - Run with OSV + NVD (NVD without key can be rate-limited but still works)
  - GHSA/Sonatype are skipped automatically when tokens are not present
  - Optional 4th profile: Power-user mode (with keys) for best coverage/rate/performance
  - Offline mode is available and works with local advisory DB/cache only
  - Power-user mode: add optional keys for better coverage/rate/performance
- Optional environment keys (power users):
  - `NVD_API_KEY`
  - `GITHUB_TOKEN`
  - `SONATYPE_TOKEN`

## Packaging

- Guide: `packaging/README.md`
- Zero-install validation: `packaging/validation/zero_install_checklist.md`

## TRA Security Checks

- Run automated TRA checks: `python3 security/run_tra_checks.py`
- OWASP ZAP baseline (web): `python3 security/run_tra_checks.py --run-zap --target-url https://example.com`
- Snyk SCA: `python3 security/run_tra_checks.py --run-snyk`
- SonarQube SAST: `python3 security/run_tra_checks.py --run-sonarqube`
- Checkmarx SAST: `python3 security/run_tra_checks.py --run-checkmarx`
- Nmap infra scan: `python3 security/run_tra_checks.py --run-nmap --target-host 127.0.0.1`
- Burp evidence attach: `python3 security/run_tra_checks.py --burp-report /path/to/burp-report.xml`
- Output report: `security/tra-report.json`
