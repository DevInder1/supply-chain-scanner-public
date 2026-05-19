"""Public Python API for embedding the scanner in other applications."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from scanner.main import build_parser, execute_scan


def run_scan(
    *,
    project_path: str = ".",
    scan: str = "all",
    run_profile: str | None = "full",
    offline: bool = False,
    output_dir: str | None = None,
    exclude_dirs: list[str] | None = None,
    nvd_api_key: str | None = None,
    github_token: str | None = None,
) -> dict[str, Any]:
    """Run a scan and return the summary payload (same shape as CLI JSON output)."""
    argv: list[str] = ["--scan", scan, "--project-path", str(project_path)]
    if run_profile:
        argv.extend(["--run-profile", run_profile])
    if offline:
        argv.append("--offline")
    if output_dir:
        argv.extend(["--output-dir", output_dir])
    for directory in exclude_dirs or []:
        argv.extend(["--exclude-dir", directory])
    if nvd_api_key:
        argv.extend(["--nvd-api-key", nvd_api_key])
    if github_token:
        argv.extend(["--github-token", github_token])

    parser = build_parser()
    args = parser.parse_args(argv)
    return execute_scan(args, emit_progress=False)


def scan_project(project_path: str, **kwargs: Any) -> dict[str, Any]:
    """Convenience wrapper for project-only scans."""
    return run_scan(project_path=project_path, scan="project", **kwargs)


def scan_system(**kwargs: Any) -> dict[str, Any]:
    """Convenience wrapper for system/extension inventory scans."""
    return run_scan(scan="system", project_path=str(Path.cwd()), **kwargs)
