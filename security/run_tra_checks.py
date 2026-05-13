from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CheckResult:
    name: str
    status: str
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "notes": self.notes,
        }


def run_command(name: str, command: list[str], cwd: Path) -> CheckResult:
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=900,
        )
        status = "passed" if proc.returncode == 0 else "failed"
        return CheckResult(
            name=name,
            status=status,
            command=command,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except FileNotFoundError:
        return CheckResult(
            name=name,
            status="skipped",
            command=command,
            exit_code=None,
            stdout="",
            stderr="",
            notes=f"Missing executable: {command[0]}",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name=name,
            status="failed",
            command=command,
            exit_code=None,
            stdout="",
            stderr="Command timed out after 900s",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TRA-oriented automated checks.")
    parser.add_argument(
        "--target-url",
        help="Optional URL for web surface testing (ZAP/Burp).",
    )
    parser.add_argument(
        "--target-host",
        help="Optional host/IP for infrastructure checks (Nmap).",
    )
    parser.add_argument(
        "--run-zap",
        action="store_true",
        help="Run OWASP ZAP baseline scan when --target-url is provided.",
    )
    parser.add_argument(
        "--run-snyk",
        action="store_true",
        help="Run Snyk SCA check (requires `snyk auth` beforehand).",
    )
    parser.add_argument(
        "--run-sonarqube",
        action="store_true",
        help="Run SonarQube scan via sonar-scanner (requires SONAR_TOKEN + project config).",
    )
    parser.add_argument(
        "--run-checkmarx",
        action="store_true",
        help="Run Checkmarx One CLI SAST scan (requires `cx` auth/project setup).",
    )
    parser.add_argument(
        "--run-nmap",
        action="store_true",
        help="Run Nmap quick vuln-oriented scan when --target-host is provided.",
    )
    parser.add_argument(
        "--burp-report",
        help="Optional path to existing Burp Suite report XML/HTML/JSON for TRA evidence attachment.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    results: list[CheckResult] = []

    # Python security checks
    if shutil.which("python3"):
        results.append(
            run_command(
                "pip-audit(requirements)",
                ["python3", "-m", "pip_audit", "-r", "requirements.txt"],
                repo_root,
            )
        )
    if shutil.which("bandit"):
        results.append(run_command("bandit(scanner)", ["bandit", "-r", "scanner"], repo_root))
    else:
        results.append(
            CheckResult(
                name="bandit(scanner)",
                status="skipped",
                command=["bandit", "-r", "scanner"],
                exit_code=None,
                stdout="",
                stderr="",
                notes="Bandit not installed",
            )
        )

    # Node/Electron dependency checks
    desktop_dir = repo_root / "apps" / "desktop"
    if desktop_dir.exists():
        results.append(
            run_command(
                "npm-audit(desktop)",
                ["npm", "audit", "--audit-level=moderate", "--json"],
                desktop_dir,
            )
        )

    # Optional OWASP ZAP baseline (web targets only)
    if args.run_zap and args.target_url:
        if shutil.which("zap-baseline.py"):
            results.append(
                run_command(
                    "owasp-zap-baseline",
                    ["zap-baseline.py", "-t", args.target_url, "-J", "-"],
                    repo_root,
                )
            )
        elif shutil.which("docker"):
            results.append(
                run_command(
                    "owasp-zap-baseline",
                    [
                        "docker",
                        "run",
                        "--rm",
                        "ghcr.io/zaproxy/zaproxy:stable",
                        "zap-baseline.py",
                        "-t",
                        args.target_url,
                        "-J",
                        "-",
                    ],
                    repo_root,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="owasp-zap-baseline",
                    status="skipped",
                    command=["docker", "run", "ghcr.io/zaproxy/zaproxy:stable", "..."],
                    exit_code=None,
                    stdout="",
                    stderr="",
                    notes="Docker is required for OWASP ZAP baseline in this script.",
                )
            )
    elif args.run_zap and not args.target_url:
        results.append(
            CheckResult(
                name="owasp-zap-baseline",
                status="skipped",
                command=["zap-baseline.py", "-t", "<target-url>"],
                exit_code=None,
                stdout="",
                stderr="",
                notes="Set --target-url to run OWASP ZAP baseline.",
            )
        )

    # Optional SCA with Snyk
    if args.run_snyk:
        results.append(run_command("snyk-test", ["snyk", "test", "--all-projects"], repo_root))

    # Optional SAST with SonarQube
    if args.run_sonarqube:
        results.append(run_command("sonarqube-scan", ["sonar-scanner"], repo_root))

    # Optional SAST with Checkmarx One CLI
    if args.run_checkmarx:
        results.append(
            run_command(
                "checkmarx-sast",
                ["cx", "scan", "create", "--scan-types", "sast", "--project-name", "supply-chain-scanner-new-dashboard", "--source", ".", "--async"],
                repo_root,
            )
        )

    # Optional infrastructure testing with Nmap
    if args.run_nmap and args.target_host:
        results.append(
            run_command(
                "nmap-quick-scan",
                ["nmap", "-sV", "-T4", args.target_host],
                repo_root,
            )
        )
    elif args.run_nmap and not args.target_host:
        results.append(
            CheckResult(
                name="nmap-quick-scan",
                status="skipped",
                command=["nmap", "-sV", "-T4", "<target-host>"],
                exit_code=None,
                stdout="",
                stderr="",
                notes="Set --target-host to run Nmap.",
            )
        )

    # Optional Burp report attachment (manual scan evidence)
    if args.burp_report:
        burp_path = Path(args.burp_report).expanduser()
        if burp_path.exists():
            results.append(
                CheckResult(
                    name="burp-report-attachment",
                    status="passed",
                    command=["attach", str(burp_path)],
                    exit_code=0,
                    stdout=str(burp_path),
                    stderr="",
                    notes="Existing Burp Suite report attached as TRA evidence.",
                )
            )
        else:
            results.append(
                CheckResult(
                    name="burp-report-attachment",
                    status="failed",
                    command=["attach", str(burp_path)],
                    exit_code=1,
                    stdout="",
                    stderr="Burp report file not found",
                )
            )

    output_dir = repo_root / "security"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "tra-report.json"
    payload = {"results": [item.to_dict() for item in results]}
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    failed = [item for item in results if item.status == "failed"]
    print(f"TRA checks complete. failed={len(failed)} report={output_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
