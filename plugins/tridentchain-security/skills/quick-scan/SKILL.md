---
description: Fast cached-only scan of project dependencies for high-severity CVEs. Uses the local advisory cache without making fresh network calls — sub-second for most projects. Use when the user wants a pre-commit check, a fast pulse on supply-chain risk, or is offline. For thorough live-advisory checks use `scan` or `supply-chain-scan` instead.
---

# Quick scan

When the user asks for a **fast**, **quick**, or **pre-commit** dependency check, or says they're offline:

1. Call the **tridentchain** MCP tool `scan_project` with:
   - `project_path` = workspace root (absolute)
   - `output_dir` = `.tridentchain-out`
   - `run_profile` = `"quick"` ← important: cached advisories only, no live fetch
   - `max_findings` = 20 (keep summaries tight)
2. **Report only HIGH and CRITICAL** findings by default; the user asked for a fast pulse, not a full triage.
3. If the cache is empty (no prior scan), tell the user explicitly and offer a `scan` (full live) run instead.

## CLI fallback

```bash
tridentchain-security --scan project --run-profile quick --project-path . --output-dir .tridentchain-out
```

## When NOT to use quick-scan

- User wants the most up-to-date data → use `scan` (live advisory fetch)
- User wants system packages or IDE extensions → use `scan-full`
- User wants to confirm a fix landed → use `validate-fixes`
