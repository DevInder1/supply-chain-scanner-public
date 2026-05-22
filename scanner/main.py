from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.core.extractor import ensure_parent, expand_path, load_config
from scanner.core.matcher import advisory_cve, match_components
from scanner.core.sbom import merge_components
from scanner.reports.generator import (
    build_report,
    write_combined_html_report,
    write_epss_remediation_html_report,
    write_html_report,
    write_json_report,
    write_vuln_fixes_html_report,
)
from scanner.scanners.jetbrains import scan_jetbrains_plugins
from scanner.scanners.project import scan_project_dependencies
from scanner.scanners.system import scan_system_packages
from scanner.scanners.vscode import scan_vscode_extensions
from scanner.sources.epss import sync_epss_scores
from scanner.sources.ghsa import sync_ghsa_advisories
from scanner.sources.kev import sync_kev_catalog
from scanner.sources.nvd import sync_nvd_advisories
from scanner.sources.osv import sync_osv_advisories
from scanner.sources.ossindex import sync_ossindex_advisories
from scanner.storage.db import VulnerabilityDatabase

logger = logging.getLogger(__name__)
_PROGRESS_ENABLED = True


def _default_config_path() -> str:
    return str((Path(__file__).resolve().parent / "config.yaml"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local-first supply chain vulnerability scanner")
    parser.add_argument("--version", "-V", action="version", version="tridentchain-security 0.1.2")
    parser.add_argument("--scan", choices=["all", "system", "project"], default="all")
    parser.add_argument(
        "--run-profile",
        choices=["quick", "full", "offline"],
        help="Preset mode for desktop integrations (quick/full/offline)",
    )
    parser.add_argument("--project-path", default=".", help="Path containing package.json for project scanning")
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Relative directory path to exclude from project dependency discovery (repeatable)",
    )
    parser.add_argument("--config", default=_default_config_path(), help="Path to the scanner config file")
    parser.add_argument("--db-path", help="Override the SQLite cache path")
    parser.add_argument("--output-dir", help="Output directory for deterministic report file names")
    parser.add_argument("--output", help="Path for the JSON report output")
    parser.add_argument("--html", help="Optional path for the HTML report output")
    parser.add_argument("--vuln-html", help="Optional path for vulnerabilities & fixes HTML report")
    parser.add_argument("--epss-html", help="Optional path for EPSS remediation HTML report")
    parser.add_argument("--combined-html", help="Path for combined project+system HTML report (requires two JSON reports)")
    parser.add_argument("--offline", action="store_true", help="Use only locally cached vulnerability data")
    parser.add_argument("--nvd-api-key", default=None, help="NVD API key for higher rate limits")
    parser.add_argument("--github-token", default=None, help="GitHub token for GHSA GraphQL queries")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Compare baseline vs after-patch scan JSON (no new scan); use with --baseline-report and --after-report",
    )
    parser.add_argument(
        "--baseline-report",
        help="Path to baseline scan-report.json or stdout summary JSON (with --validate)",
    )
    parser.add_argument(
        "--after-report",
        help="Path to after-patch scan-report.json or stdout summary JSON (with --validate)",
    )
    return parser


def _load_dotenv() -> None:
    """Load .env file from the project root into os.environ (if it exists)."""
    import os as _os
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not env_file.is_file():
        return
    with open(env_file) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if value and value[0] in ('"', "'") and value[-1] == value[0]:
                value = value[1:-1]
            _os.environ.setdefault(key, value)


def execute_scan(args: argparse.Namespace, *, emit_progress: bool = True) -> dict[str, Any]:
    """Run the scanner pipeline and return a summary payload."""
    global _PROGRESS_ENABLED
    previous_progress = _PROGRESS_ENABLED
    _PROGRESS_ENABLED = emit_progress
    _load_dotenv()
    _apply_run_profile_defaults(args)
    if args.scan in {"all", "project"}:
        project_root = expand_path(args.project_path)
        if not project_root.is_dir():
            raise ValueError(f"project path is not a directory: {project_root}")
        args.project_path = str(project_root)
    config = load_config(args.config)
    storage_config = config.get("storage", {})
    scanner_config = config.get("scanners", {})
    scanner_config["_cli_exclude_dirs"] = list(args.exclude_dir or [])
    report_config = config.get("reports", {})
    source_config = config.get("sources", {})

    db_path = expand_path(args.db_path or storage_config.get("db_path", "scanner/storage/vuln_cache.db"))
    json_output, html_output, vuln_html_output, epss_html_output = _resolve_output_paths(args, report_config)

    _emit_progress("Collecting components")
    components = _collect_components(
        scan_target=args.scan,
        project_path=args.project_path,
        scanner_config=scanner_config,
    )
    components = merge_components(components)

    import os as _os
    nvd_api_key = args.nvd_api_key or _os.environ.get("NVD_API_KEY") or source_config.get("nvd_api_key")
    github_token = args.github_token or _os.environ.get("GITHUB_TOKEN") or source_config.get("github_token")
    sonatype_token = _os.environ.get("SONATYPE_TOKEN") or source_config.get("sonatype_token")

    db = VulnerabilityDatabase(db_path)
    source_coverage = _init_source_coverage(
        offline=args.offline,
        has_nvd_key=bool(nvd_api_key),
        has_ghsa_token=bool(github_token),
        has_sonatype_token=bool(sonatype_token),
    )
    report: dict[str, Any] | None = None
    try:
        _emit_progress("Starting advisory synchronization")
        # --- Source 1: OSV ---
        _run_source_sync(
            source_coverage=source_coverage,
            source_name="osv",
            progress_message="Syncing OSV advisories",
            sync_fn=sync_osv_advisories,
            sync_db=db,
            components=components,
            offline=args.offline,
            base_url=source_config.get("osv_base_url", "https://api.osv.dev/v1/querybatch"),
            max_hydrate_requests=int(source_config.get("osv_max_hydrate_requests", 50)),
        )
        # --- Source 2: NVD (CPE-based) ---
        _run_source_sync(
            source_coverage=source_coverage,
            source_name="nvd",
            progress_message="Syncing NVD advisories",
            sync_fn=sync_nvd_advisories,
            sync_db=db,
            components=components,
            offline=args.offline,
            api_key=nvd_api_key,
            base_url=source_config.get("nvd_base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
            max_requests_without_key=int(source_config.get("nvd_max_requests_without_key", 10)),
        )
        # --- Source 3: GHSA (GitHub Advisory Database) ---
        _run_source_sync(
            source_coverage=source_coverage,
            source_name="ghsa",
            progress_message="Syncing GHSA advisories",
            sync_fn=sync_ghsa_advisories,
            sync_db=db,
            components=components,
            offline=args.offline,
            github_token=github_token,
            base_url=source_config.get("ghsa_base_url", "https://api.github.com/graphql"),
        )
        # --- Source 4: Sonatype Guide ---
        _run_source_sync(
            source_coverage=source_coverage,
            source_name="sonatype",
            progress_message="Syncing Sonatype advisories",
            sync_fn=sync_ossindex_advisories,
            sync_db=db,
            components=components,
            offline=args.offline,
            sonatype_token=sonatype_token,
            base_url=source_config.get("sonatype_base_url", "https://api.guide.sonatype.com"),
        )
        # --- Enrichment: KEV ---
        _emit_progress("Syncing KEV catalog")
        sync_kev_catalog(
            db,
            offline=args.offline,
            url=source_config.get(
                "kev_url",
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            ),
        )

        advisories_by_component = db.advisory_lookup()
        nvd_data = db.nvd_lookup()
        ghsa_data = db.ghsa_lookup()
        ossindex_data = db.ossindex_lookup()

        preliminary_findings = match_components(
            components, advisories_by_component,
            nvd_lookup=nvd_data, ghsa_lookup=ghsa_data, ossindex_lookup=ossindex_data,
        )
        sync_epss_scores(
            [cve for cve in (advisory_cve_item(item) for item in preliminary_findings) if cve],
            db,
            offline=args.offline,
            base_url=source_config.get("epss_base_url", "https://api.first.org/data/v1/epss"),
        )

        findings = match_components(
            components,
            advisories_by_component,
            epss_lookup=db.epss_lookup(),
            kev_lookup=db.kev_lookup(),
            nvd_lookup=nvd_data,
            ghsa_lookup=ghsa_data,
            ossindex_lookup=ossindex_data,
        )
        report = build_report(components, findings, advisories_by_component)
        report["source_coverage"] = source_coverage
        _emit_progress("Writing reports")
        write_json_report(report, json_output)
        if html_output:
            write_html_report(report, html_output)
        if vuln_html_output:
            write_vuln_fixes_html_report(report, vuln_html_output)
        if epss_html_output:
            write_epss_remediation_html_report(report, epss_html_output)
    finally:
        db.close()
        _PROGRESS_ENABLED = previous_progress

    if report is None:
        raise RuntimeError("scan failed before report generation")

    return _build_summary_payload(
        report,
        json_output,
        html_output,
        vuln_html_output,
        epss_html_output,
        args.run_profile,
    )


def execute_validate(args: argparse.Namespace) -> dict[str, Any]:
    """Compare two scan reports (Daybreak-style patch validation)."""
    from scanner.integrations import validate_after_patch
    from scanner.integrations.validate_cli import load_scan_payload

    if not args.baseline_report or not args.after_report:
        raise ValueError("--validate requires --baseline-report and --after-report")
    baseline = load_scan_payload(args.baseline_report)
    after = load_scan_payload(args.after_report)
    return validate_after_patch(baseline, after)


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.validate:
            summary = execute_validate(args)
        else:
            summary = execute_scan(args, emit_progress=True)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2))
    return 0


def _init_source_coverage(
    *,
    offline: bool,
    has_nvd_key: bool,
    has_ghsa_token: bool,
    has_sonatype_token: bool,
) -> dict[str, dict[str, Any]]:
    coverage = {
        "osv": {"enabled": not offline, "status": "pending", "reason": ""},
        "nvd": {"enabled": not offline, "status": "pending", "reason": ""},
        "ghsa": {"enabled": (not offline) and has_ghsa_token, "status": "pending", "reason": ""},
        "sonatype": {"enabled": (not offline) and has_sonatype_token, "status": "pending", "reason": ""},
    }
    if offline:
        for source in coverage.values():
            source["status"] = "skipped"
            source["reason"] = "offline mode"
    else:
        if not has_ghsa_token:
            coverage["ghsa"]["status"] = "skipped"
            coverage["ghsa"]["reason"] = "missing GITHUB_TOKEN"
        if not has_sonatype_token:
            coverage["sonatype"]["status"] = "skipped"
            coverage["sonatype"]["reason"] = "missing SONATYPE_TOKEN"
    return coverage


def _run_source_sync(
    *,
    source_coverage: dict[str, dict[str, Any]],
    source_name: str,
    progress_message: str,
    sync_fn: Any,
    sync_db: VulnerabilityDatabase,
    **kwargs: Any,
) -> None:
    status = source_coverage.get(source_name, {})
    if status.get("status") == "skipped":
        return
    if not status.get("enabled", True):
        status["status"] = "skipped"
        if not status.get("reason"):
            status["reason"] = "disabled"
        return
    _emit_progress(progress_message)
    try:
        kwargs["db"] = sync_db
        sync_fn(**kwargs)
        status["status"] = "completed"
    except Exception as exc:  # noqa: BLE001
        status["status"] = "error"
        status["reason"] = str(exc)
        logger.warning("Source '%s' sync failed: %s", source_name, exc)


def _emit_progress(message: str) -> None:
    if not _PROGRESS_ENABLED:
        return
    print(f"[progress] {message}", flush=True)


def _apply_run_profile_defaults(args: argparse.Namespace) -> None:
    if not args.run_profile:
        return
    if args.run_profile == "offline":
        args.offline = True
    if args.run_profile == "quick" and args.scan == "all":
        args.scan = "project"


def _resolve_output_paths(
    args: argparse.Namespace,
    report_config: dict[str, Any],
) -> tuple[Path, Path | None, Path | None, Path | None]:
    if args.output_dir:
        output_dir = expand_path(args.output_dir)
        json_output = ensure_parent(output_dir / "scan-report.json")
        html_output = ensure_parent(output_dir / "scan-report.html")
        vuln_html_output = ensure_parent(output_dir / "scan-vulnerabilities.html")
        epss_html_output = ensure_parent(output_dir / "scan-remediation-epss.html")
        return json_output, html_output, vuln_html_output, epss_html_output

    json_output = ensure_parent(args.output or report_config.get("json_output", "scanner/report.json"))
    html_output = ensure_parent(args.html or report_config.get("html_output", "scanner/report.html")) if args.html else None
    vuln_html_output = ensure_parent(args.vuln_html) if args.vuln_html else None
    epss_html_output = ensure_parent(args.epss_html) if args.epss_html else None
    return json_output, html_output, vuln_html_output, epss_html_output


def _collect_components(
    *,
    scan_target: str,
    project_path: str,
    scanner_config: dict[str, Any],
) -> list:
    components = []
    if scan_target in {"all", "system"}:
        _emit_progress("Scanning system packages and developer applications")
        with ThreadPoolExecutor(max_workers=3) as executor:
            system_future = executor.submit(scan_system_packages)
            vscode_future = executor.submit(scan_vscode_extensions, scanner_config.get("vscode_path"))
            jetbrains_future = executor.submit(scan_jetbrains_plugins, scanner_config.get("jetbrains_paths"))
            components.extend(system_future.result())
            _emit_progress("Scanning VS Code extensions")
            components.extend(vscode_future.result())
            _emit_progress("Scanning JetBrains IDE and plugins")
            components.extend(jetbrains_future.result())
    if scan_target in {"all", "project"}:
        _emit_progress("Scanning project dependencies from selected directory")
        configured_excludes = scanner_config.get("project_exclude_dirs", [])
        cli_excludes = scanner_config.get("_cli_exclude_dirs", [])
        exclude_dirs = [*configured_excludes, *cli_excludes]
        components.extend(scan_project_dependencies(project_path, exclude_dirs=exclude_dirs))
    return components


def advisory_cve_item(finding: dict[str, Any]) -> str | None:
    if finding.get("cve"):
        return str(finding["cve"])
    advisory_id = finding.get("advisory_id")
    if isinstance(advisory_id, str) and advisory_id.startswith("CVE-"):
        return advisory_id
    return None


def _build_summary_payload(
    report: dict[str, Any],
    json_output: Path,
    html_output: Path | None,
    vuln_html_output: Path | None = None,
    epss_html_output: Path | None = None,
    run_profile: str | None = None,
) -> dict[str, Any]:
    summary = report["summary"]
    coverage = report.get("scan_coverage", {})
    vulns = report.get("vulnerabilities", [])
    vuln_by_type = {"project": 0, "system": 0, "extension": 0, "other": 0}
    for entry in vulns:
        comp_type = str(entry.get("component", {}).get("type", "")).lower()
        bucket = comp_type if comp_type in vuln_by_type else "other"
        vuln_by_type[bucket] += len(entry.get("advisories", []))
    payload: dict[str, Any] = {
        "summary": summary,
        "components_scanned": report["components_scanned"],
        "scan_coverage": coverage,
        "vulnerability_breakdown_by_type": vuln_by_type,
        "osv_queryable": coverage.get("osv_queryable_components", 0),
        "osv_unqueryable": coverage.get("osv_unqueryable_components", 0),
        "intelligence_sources": report.get("intelligence_sources", {}),
        "affected_components": [
            {
                "name": v["component"]["name"],
                "version": v["component"]["version"],
                "vulnerabilities": len(v.get("advisories", [])),
                "severity": v.get("severity_summary", {}),
            }
            for v in vulns
        ],
        "report_path": str(json_output),
        "run_profile": run_profile or "custom",
        "output_paths": {
            "json": str(json_output),
            "html": str(html_output) if html_output else None,
            "vulnerabilities_html": str(vuln_html_output) if vuln_html_output else None,
            "epss_remediation_html": str(epss_html_output) if epss_html_output else None,
        },
    }
    if html_output:
        payload["html_report_path"] = str(html_output)
    if vuln_html_output:
        payload["vuln_fixes_report_path"] = str(vuln_html_output)
    if epss_html_output:
        payload["epss_remediation_report_path"] = str(epss_html_output)
    return payload


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130) from None