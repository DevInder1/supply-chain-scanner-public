---
description: Validate dependency upgrades by re-scanning and comparing TridentChain results
---

# Validate fixes after patch

When the user upgrades dependencies or asks to confirm a fix:

1. Ensure a **baseline** scan exists (run `scan_project` or `scan_full` first if needed).
2. Apply or confirm dependency upgrades (`npm update`, `pip install -U`, etc.).
3. Run the **same scan** again on the same `project_path`.
4. Call **`validate_after_patch`** with:
   - `baseline_json`: full JSON string from the first scan tool result
   - `after_patch_json`: full JSON string from the second scan
5. Report **`resolved_count`**, **`remaining_count`**, **`new_count`**, and **`validation_passed`**.

## CLI fallback

Run `tridentchain-security` twice with the same `--project-path` and `--output-dir`, then compare `affected_components` in the JSON summaries.
