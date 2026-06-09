---
description: Explain why a specific vulnerable package is in the project — direct vs transitive dependency, which CVE IDs apply, EPSS exploit-probability score, whether it's on the CISA KEV catalog, and the recommended fix command. Use when the user asks "why is X vulnerable", "where does X come from", or "is X actually exploitable".
---

# Why is this package vulnerable

When the user asks about a single specific package — "why is `lodash@4.17.15` flagged?", "where does `brace-expansion` come from?", "is `requests` actually exploitable?":

1. Call the **tridentchain** MCP tool `scan_project` with the workspace path (or use the most recent `.tridentchain-out/scan-report.json` if available).
2. From `raw_summary.affected_components`, find the entry matching the package name and version.
3. Report in this order:
   - **Package + version + ecosystem** (e.g., `lodash@4.17.15` (npm))
   - **Is it a direct or transitive dependency?** Walk the lockfile path (look in `raw_summary.scan_coverage.by_source` for the manifest, then read the lockfile to identify the parent that pulled it in). Show the dep chain: `your-app → minimatch@3.1.5 → brace-expansion@5.0.5`.
   - **CVE IDs affecting this exact version** — list every CVE/GHSA ID.
   - **EPSS exploit-probability score** (0–1; higher = more likely actively exploited). Anything above 0.1 deserves attention; above 0.5 is urgent.
   - **CISA KEV status** — if listed, flag URGENT.
   - **Fix version** — the lowest version that resolves all listed CVEs.
   - **Recommended command** — the exact shell command to upgrade (e.g., `cd <project> && npm install minimatch@latest`).
4. End with one sentence: should the user fix it now, or is it low-priority?

## CLI fallback

```bash
tridentchain-security --scan project --project-path . --output-dir .tridentchain-out
# Then jq into the report:
jq '.affected_components[] | select(.name == "lodash")' .tridentchain-out/scan-report.json
```

## Don't

- Don't auto-apply the fix command. Read it to the user; let them decide.
- Don't recommend `npm audit fix --force` without explicit user consent — it can introduce breaking changes.
