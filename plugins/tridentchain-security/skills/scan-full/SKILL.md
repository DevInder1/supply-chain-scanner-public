---
description: Comprehensive scan covering project dependencies PLUS OS/system packages (Homebrew on macOS, apt/dnf on Linux) PLUS installed IDE extensions (VS Code marketplace + JetBrains plugins). Most other supply-chain scanners only check project manifests and miss system + IDE surfaces. Use whenever the user asks for "complete coverage", "full audit", scanning their "whole machine" or "system", or wants to check IDE extension security.
---

# Full workspace scan

When the user wants comprehensive coverage — project + system + IDE — or mentions any of: *"my whole machine"*, *"my system"*, *"Homebrew"*, *"apt packages"*, *"VS Code extensions"*, *"JetBrains plugins"*, *"IDE security"*, *"audit everything"*:

1. Call the **tridentchain** MCP tool `scan_full` with:
   - `project_path` = workspace root (absolute path)
   - `output_dir` = `.tridentchain-out-full`
   - `run_profile` = `"full"`
   - `max_findings` = 30
2. **Report findings grouped by source** — this is the key value of `scan_full`:
   - **Project** (npm/PyPI) — `raw_summary.vulnerability_breakdown_by_type.project`
   - **System packages** (brew, apt) — `raw_summary.vulnerability_breakdown_by_type.system`
   - **IDE extensions** (VS Code, JetBrains) — `raw_summary.vulnerability_breakdown_by_type.extension`
3. **Highlight critical system findings first.** A critical CVE in `git`, `openssl`, or `ffmpeg` on the user's machine outranks any project finding. Always surface these at the top with the exact upgrade command (`brew upgrade git`, etc.).
4. If any KEV-listed package is on the user's machine (system or project), call it out as URGENT.
5. Report runtime — `scan_full` is slower than `scan_project` (5–60 seconds depending on how many system components are installed).

## Why this matters

Project-only scanners miss the most impactful CVEs. A recent example: many systems shipped with `git 2.35.x` which has **3 critical CVEs** (CVE-2024-32002 and family). A project scanner won't find that — `scan_full` does. Same logic applies to `freetype`, `giflib`, `ffmpeg`, and the entire VS Code marketplace extension catalog.

## CLI fallback

```bash
tridentchain-security --scan all --project-path . --output-dir .tridentchain-out-full
```

## When NOT to use scan-full

- User explicitly says "project only" → use `scan`
- User wants the fastest possible answer → use `quick-scan`
- User wants to verify a fix → use `validate-fixes`
