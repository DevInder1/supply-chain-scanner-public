---
description: Re-scan after a dependency upgrade and confirm the CVEs are actually resolved. Use when the user has just run `npm update`, `pip install -U`, applied a patch, or otherwise upgraded packages and wants verification. Diffs a baseline scan against the post-patch scan and reports resolved_count, remaining_count, new_count, and validation_passed.
---

# Validate fixes after patch

When the user upgrades dependencies or asks to confirm a fix:

## Workflow

1. **Baseline** — Run `scan_project` or `scan_full` on `project_path` (MCP) or:
   ```bash
   tridentchain-security --scan project --project-path <path> --output-dir .tridentchain-out
   ```
   Save the JSON summary or `scan-report.json` as baseline if the output dir will be overwritten.

2. **Upgrade** — Apply dependency changes (`npm update`, `pip install -U`, etc.).

3. **Re-scan** — Run the **same scan** again on the same `project_path`.

4. **Validate** — Use one of:
   - **MCP:** `validate_after_patch` with `baseline_json` and `after_patch_json` (full tool result strings)
   - **CLI:** 
     ```bash
     tridentchain-security --validate \
       --baseline-report <baseline.json> \
       --after-report .tridentchain-out/scan-report.json
     ```

5. **Report** — `resolved_count`, `remaining_count`, `new_count`, `validation_passed`.

## Requirements

- `tridentchain-security>=0.1.1` and `tridentchain-mcp` for MCP path
- Pin `tridentchain-security==0.1.0` only supports manual JSON comparison (no `--validate`)

## CLI fallback (no MCP)

Run `tridentchain-security` twice, then `--validate` with two report paths. See [docs/CAPABILITIES.md](../../../docs/CAPABILITIES.md).
