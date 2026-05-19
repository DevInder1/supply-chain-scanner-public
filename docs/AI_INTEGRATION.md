# AI & Automation Integration

TridentChain Security can be used by AI assistants, CI pipelines, and custom tools **without cloning the repository** — install from PyPI and call the CLI or Python API.

---

## Option A — CLI (any agent that runs shell commands)

### Install once

```bash
pip3 install tridentchain-security
```

### Run scan (JSON on stdout)

```bash
tridentchain-security \
  --scan all \
  --project-path /path/to/repo \
  --output-dir /tmp/tridentchain-out \
  --run-profile full
```

The last JSON object on stdout is the scan summary (findings count, report paths, source status).

### Parse in Python

```python
import json
import subprocess

result = subprocess.run(
    [
        "tridentchain-security",
        "--scan", "project",
        "--project-path", ".",
        "--output-dir", "scanner-output",
    ],
    capture_output=True,
    text=True,
    check=True,
)
lines = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("{")]
summary = json.loads(lines[-1])
print(summary.get("summary"))
```

### Cursor / Copilot / custom agent prompt snippet

```text
To scan this project for supply-chain vulnerabilities, run:
  tridentchain-security --scan all --project-path <workspace_root> --output-dir .tridentchain-output
Then read .tridentchain-output/scan-report.json and scan-vulnerabilities.html.
No API keys are required for the default full profile.
```

---

## Option B — Python API (embedded agents)

```python
from scanner import run_scan

summary = run_scan(
    project_path="/path/to/repo",
    scan="all",
    run_profile="full",
    output_dir="scanner-output",
)

print(summary["summary"])
# HTML reports: summary["output_paths"]
```

Optional keys (environment or kwargs):

- `nvd_api_key` / `NVD_API_KEY`
- `github_token` / `GITHUB_TOKEN`

---

## Option C — Desktop app (human + AI hybrid)

1. `pip3 install tridentchain-security`
2. `cd apps/desktop && npm install && npm run start`
3. User selects project path; agent can read generated reports from the output folder.

No repo clone required if the pip package is installed.

---

## Output for agents

| File | Best for |
|------|----------|
| `scan-report.json` | Structured parsing |
| `scan-vulnerabilities.html` | Human review |
| `scan-remediation-epss.html` | Prioritized fixes |

---

## Security notes for AI workflows

- Do **not** pass API keys in chat; use environment variables or a local `.env` (gitignored).
- Scope scans with `--project-path` to the workspace root.
- Use `--run-profile quick` for faster iteration; `full` for complete coverage.

---

## Related

- [INSTALL_AND_USE.md](INSTALL_AND_USE.md)
- [CROSS_PLATFORM.md](CROSS_PLATFORM.md)
- [cli-contract.md](cli-contract.md)
- [DISTRIBUTION_VERIFICATION.md](DISTRIBUTION_VERIFICATION.md)
