from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bundle scanner runtime for desktop installers")
    parser.add_argument("--target", choices=["macos", "linux", "windows"], required=True)
    return parser.parse_args()


def run(cmd: list[str], cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=cwd, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    runtime_root = repo_root / "packaging" / "runtime"
    scanner_bundle = runtime_root / "scanner"
    python_bundle = runtime_root / "python"

    if scanner_bundle.exists():
        shutil.rmtree(scanner_bundle)
    if python_bundle.exists():
        shutil.rmtree(python_bundle)
    scanner_bundle.mkdir(parents=True, exist_ok=True)

    shutil.copytree(repo_root / "scanner", scanner_bundle / "scanner")
    if (repo_root / "main.py").exists():
        shutil.copy2(repo_root / "main.py", scanner_bundle / "main.py")

    # Optional helper: if pyenv or system Python is available, copy interpreter as seed runtime.
    if args.target == "windows":
        candidate = shutil.which("python")
        executable_name = "python.exe"
    else:
        candidate = shutil.which("python3") or shutil.which("python")
        executable_name = "python3"

    if candidate:
        python_bundle.mkdir(parents=True, exist_ok=True)
        target_exec = python_bundle / executable_name
        shutil.copy2(candidate, target_exec)

    print(f"Runtime bundle created at: {runtime_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
