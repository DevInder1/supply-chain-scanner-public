---
description: Scan a workspace for supply-chain CVEs across project dependencies, system packages (Homebrew/apt), and IDE extensions (VS Code, JetBrains). Findings ranked by EPSS exploit probability and CISA KEV presence — not just CVSS severity. Use when the user asks about supply-chain risk, dependency vulnerabilities, or wants broader coverage than a project-only npm scan.
---

# Supply chain scan

When the user asks about dependency vulnerabilities, CVEs, supply-chain risk, IDE extension security, or wants to audit `package.json` / lockfiles / `requirements.txt`:

1. Use the **tridentchain** MCP tools — pick the right scope:
   - **`scan_project`** — fast scan of project deps only (npm, PyPI). Best when the user explicitly says "project only" or wants a fast pre-commit check.
   - **`scan_full`** — comprehensive: project deps + Homebrew/apt packages + VS Code + JetBrains extensions. Use when the user says "everything", "system", "machine", "IDE", or asks about extension security.
2. Pass **`project_path`** as the workspace root (absolute path).
3. Use **`output_dir`** `.tridentchain-out` under the project unless the user specifies another path.
4. **Lead the summary with EPSS-prioritised findings** — the top 3 by EPSS score are the actual fix-first list. Then summarise by severity. Mention `output_paths.epss_remediation_html` for the prioritised view.
5. If KEV findings are present (`raw_summary.intelligence_sources.sources_used.kev`), call them out separately — these are actively exploited in the wild.
6. **No API keys** are required for the default profile.

## CLI fallback (if MCP unavailable)

```bash
tridentchain-security --scan project --project-path <workspace> --output-dir .tridentchain-out
# Or for full system coverage:
tridentchain-security --scan all --project-path <workspace> --output-dir .tridentchain-out
```

Read `.tridentchain-out/scan-report.json` for the full data; `scan-remediation-epss.html` for the prioritised remediation queue.

## Do not

- Put API keys in chat; use environment variables only.
- Scan paths outside the user's project without permission.
