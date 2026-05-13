# Runtime Bundle Layout

This folder is copied into app installer resources as `runtime/`.

Expected structure:

- `runtime/python/` -> bundled Python interpreter
- `runtime/scanner/` -> scanner source and entrypoint

During packaging, populate this folder via:

- `python3 packaging/scripts/bundle_scanner_runtime.py --target macos`
- `python3 packaging/scripts/bundle_scanner_runtime.py --target linux`
- `python3 packaging/scripts/bundle_scanner_runtime.py --target windows`
