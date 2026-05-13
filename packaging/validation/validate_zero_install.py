from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke-check scanner contract for desktop zero-install builds")
    parser.add_argument("--python", default=sys.executable, help="Python interpreter path")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--output-dir", default="scanner/desktop-validation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    output_dir = repo_root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        args.python,
        "-m",
        "scanner.main",
        "--run-profile",
        "quick",
        "--scan",
        "project",
        "--project-path",
        ".",
        "--output-dir",
        str(output_dir),
    ]
    proc = subprocess.run(cmd, cwd=repo_root, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(proc.returncode)

    summary = _parse_last_json_block(proc.stdout)
    if not summary:
        raise SystemExit("Could not parse summary JSON from scanner stdout")

    paths = summary.get("output_paths", {})
    required = [
        Path(paths.get("json", "")),
        Path(paths.get("html", "")),
        Path(paths.get("vulnerabilities_html", "")),
    ]
    missing = [str(path) for path in required if not str(path) or not path.exists()]
    if missing:
        raise SystemExit(f"Missing output files: {missing}")

    print(json.dumps({"status": "ok", "outputs": paths}, indent=2))
    return 0


def _parse_last_json_block(stdout: str) -> dict | None:
    lines = stdout.strip().split("\n")
    for index in range(len(lines) - 1, -1, -1):
        if not lines[index].strip().startswith("{"):
            continue
        candidate = "\n".join(lines[index:])
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


if __name__ == "__main__":
    raise SystemExit(main())
