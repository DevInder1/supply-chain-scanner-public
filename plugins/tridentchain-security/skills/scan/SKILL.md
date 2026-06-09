---
description: Full project dependency scan with live advisory fetch (OSV, NVD, GHSA) and EPSS exploit-probability + CISA KEV prioritisation. Covers npm and PyPI manifests + lockfiles. Use when the user wants thorough, up-to-date supply-chain CVE coverage for their project — but does NOT need system packages or IDE extensions (for those use `scan-full`).
---

# Project scan

When the user asks to scan a project for vulnerabilities, audit `package.json` / `requirements.txt`, or check dependency security:

1. Call the **tridentchain** MCP tool `scan_project` with:
   - `project_path` = workspace root (absolute path)
   - `output_dir` = `.tridentchain-out`
   - `run_profile` = `"full"` (live advisory fetch — default)
   - `max_findings` = 50
2. **Lead with EPSS-prioritised findings.** Pull the top-5 by EPSS score from `raw_summary.affected_components`, ranked by `epss_score`. These are the actual fix-first list.
3. Then summarise severity totals (critical / high / medium / low).
4. If any finding is in the **CISA KEV** catalog (`source: "kev"`), tag it clearly — these are actively exploited in the wild.
5. Point the user at `output_paths.epss_remediation_html` for the prioritised remediation queue (with copy-paste fix commands).

## When to use `scan` vs siblings

| Situation | Use |
|---|---|
| User wants project deps only, live data | `scan` (this) |
| User is in a hurry / offline | `quick-scan` |
| User says "system", "IDE", "extensions", "machine", "everything" | `scan-full` |
| User upgraded packages and wants to verify | `validate-fixes` |
| User wants to drill into ONE package | `why` |
| User wants a fix recipe | `fix-plan` |

## CLI fallback

```bash
tridentchain-security --scan project --project-path . --output-dir .tridentchain-out
```
