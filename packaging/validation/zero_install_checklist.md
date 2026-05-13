# Zero-Install Validation Checklist

Run these checks on clean machines (or fresh VMs) without preinstalling Python, pip, npm, or scanner dependencies.

## macOS

- Install `.dmg` build.
- Launch app and run `quick` profile on a sample project.
- Confirm logs stream in-app and scan completes.
- Confirm generated files exist:
  - `scan-report.json`
  - `scan-report.html`
  - `scan-vulnerabilities.html`
- Confirm `Open JSON/HTML report` buttons open correct files.

## Windows

- Install `.exe` (NSIS) build.
- Launch app and run `full` profile.
- Confirm system scan and project scan complete.
- Confirm no external Python/npm install prompt is required.

## Linux

- Run `.AppImage` build.
- Execute `offline` profile.
- Confirm cached database mode works and summary renders.

## Pass Criteria

- Scanner runs successfully from desktop app on all three OS targets.
- No manual package/runtime installation is needed by end users.
- Output schema includes `output_paths` and is parsed by renderer.
