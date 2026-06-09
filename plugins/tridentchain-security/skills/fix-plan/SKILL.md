---
description: Generate an EPSS/KEV-prioritised remediation plan from a scan. Returns the top findings ranked by real-world exploitation risk with copy-paste upgrade commands, semver-jump risk classification (PATCH/MINOR/MAJOR), and a recommendation per package. Use when the user asks for "what should I fix first", "remediation plan", "how do I patch this", or "fix script".
---

# Fix plan

When the user asks for a remediation plan, fix recipe, or "what should I patch first":

1. Run a scan first (use `scan` or `scan-full` per scope). If a recent `.tridentchain-out/scan-report.json` exists, you may reuse it.
2. From `raw_summary.affected_components`, build a prioritised plan:
   - **Sort by EPSS score descending** — the user wants the actively-exploited ones first.
   - For each finding, capture: package name, current version, fix version, ecosystem, CVE IDs, EPSS score, KEV status.
3. Present the plan as a table or numbered list. For each line include:
   - **Risk badge:** `URGENT` if KEV-listed OR EPSS > 0.5; `HIGH` if EPSS > 0.1; `INFO` otherwise.
   - **Semver jump:** PATCH (e.g., 5.0.5 → 5.0.6), MINOR (5.0.5 → 5.1.0), or MAJOR (5.x → 6.x). MAJOR bumps need user review.
   - **Exact command** the user can copy-paste:
     - npm: `cd <manifest_dir> && npm install <pkg>@<fix_version>`
     - pip: `pip install --upgrade '<pkg>>=<fix_version>'`
     - Homebrew (system): `brew upgrade <pkg>`
4. After the plan, suggest the user re-run `validate-fixes` once the patches are applied — this closes the loop and verifies the CVEs are actually resolved.

## Important constraints

- **Never apply the commands yourself.** Present the plan; let the user run it. Auto-applying dependency upgrades is the user's decision.
- **Flag MAJOR semver bumps explicitly.** They often introduce breaking changes; do not group them with PATCH bumps.
- **Group by manifest.** If there are multiple `package.json` files or multiple `requirements.txt` in the project, separate the commands per directory.

## CLI fallback (no MCP)

```bash
tridentchain-security --scan project --project-path . --output-dir .tridentchain-out
# Open the EPSS-prioritised remediation report:
open .tridentchain-out/scan-remediation-epss.html
```

The HTML report already shows the EPSS-ranked remediation queue with per-package fix commands.
