from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.core.extractor import ensure_parent, expand_path, load_config
from scanner.core.matcher import advisory_cve, match_components
from scanner.core.sbom import merge_components
from scanner.reports.generator import build_report, write_html_report, write_json_report, write_vuln_fixes_html_report, write_combined_html_report
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local-first supply chain vulnerability scanner")
    parser.add_argument("--scan", choices=["all", "system", "project"], default="all")
    parser.add_argument("--project-path", default=".", help="Path containing package.json for project scanning")
    parser.add_argument("--config", default="scanner/config.yaml", help="Path to the scanner config file")
    parser.add_argument("--db-path", help="Override the SQLite cache path")
    parser.add_argument("--output", help="Path for the JSON report output")
    parser.add_argument("--html", help="Optional path for the HTML report output")
    parser.add_argument("--vuln-html", help="Optional path for vulnerabilities & fixes HTML report")
    parser.add_argument("--combined-html", help="Path for combined project+system HTML report (requires two JSON reports)")
    parser.add_argument("--offline", action="store_true", help="Use only locally cached vulnerability data")
    parser.add_argument("--nvd-api-key", default=None, help="NVD API key for higher rate limits")
    parser.add_argument("--github-token", default=None, help="GitHub token for GHSA GraphQL queries")
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


def main() -> int:
    _load_dotenv()
    args = build_parser().parse_args()
    config = load_config(args.config)
    storage_config = config.get("storage", {})
    scanner_config = config.get("scanners", {})
    report_config = config.get("reports", {})
    source_config = config.get("sources", {})

    db_path = expand_path(args.db_path or storage_config.get("db_path", "scanner/storage/vuln_cache.db"))
    json_output = ensure_parent(args.output or report_config.get("json_output", "scanner/report.json"))
    html_output = ensure_parent(args.html or report_config.get("html_output", "scanner/report.html")) if args.html else None
    vuln_html_output = ensure_parent(args.vuln_html) if args.vuln_html else None

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
    try:
        # --- Source 1: OSV ---
        sync_osv_advisories(
            components,
            db,
            offline=args.offline,
            base_url=source_config.get("osv_base_url", "https://api.osv.dev/v1/querybatch"),
        )
        # --- Source 2: NVD (CPE-based) ---
        sync_nvd_advisories(
            components,
            db,
            offline=args.offline,
            api_key=nvd_api_key,
            base_url=source_config.get("nvd_base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        )
        # --- Source 3: GHSA (GitHub Advisory Database) ---
        sync_ghsa_advisories(
            components,
            db,
            offline=args.offline,
            github_token=github_token,
            base_url=source_config.get("ghsa_base_url", "https://api.github.com/graphql"),
        )
        # --- Source 4: Sonatype Guide ---
        sync_ossindex_advisories(
            components,
            db,
            offline=args.offline,
            sonatype_token=sonatype_token,
            base_url=source_config.get("sonatype_base_url", "https://api.guide.sonatype.com"),
        )
        # --- Enrichment: KEV ---
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
        write_json_report(report, json_output)
        if html_output:
            write_html_report(report, html_output)
        if vuln_html_output:
            write_vuln_fixes_html_report(report, vuln_html_output)
    finally:
        db.close()

    _print_summary(report, json_output, html_output, vuln_html_output)
    return 0


def _collect_components(
    *,
    scan_target: str,
    project_path: str,
    scanner_config: dict[str, Any],
) -> list:
    components = []
    if scan_target in {"all", "system"}:
        components.extend(scan_system_packages())
        components.extend(scan_vscode_extensions(scanner_config.get("vscode_path")))
        components.extend(scan_jetbrains_plugins(scanner_config.get("jetbrains_paths")))
    if scan_target in {"all", "project"}:
        components.extend(scan_project_dependencies(project_path))
    return components


def advisory_cve_item(finding: dict[str, Any]) -> str | None:
    if finding.get("cve"):
        return str(finding["cve"])
    advisory_id = finding.get("advisory_id")
    if isinstance(advisory_id, str) and advisory_id.startswith("CVE-"):
        return advisory_id
    return None


def _print_summary(report: dict[str, Any], json_output: Path, html_output: Path | None, vuln_html_output: Path | None = None) -> None:
    summary = report["summary"]
    coverage = report.get("scan_coverage", {})
    vulns = report.get("vulnerabilities", [])
    payload: dict[str, Any] = {
        "summary": summary,
        "components_scanned": report["components_scanned"],
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
    }
    if html_output:
        payload["html_report_path"] = str(html_output)
    if vuln_html_output:
        payload["vuln_fixes_report_path"] = str(vuln_html_output)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())