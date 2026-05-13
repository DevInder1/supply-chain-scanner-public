from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from functools import cmp_to_key
from html import escape
from pathlib import Path
from typing import Any

from scanner.core.matcher import summarize_findings
from scanner.core.matcher import compare_versions
from scanner.core.sbom import Component, export_sbom
from scanner.sources.osv import map_osv_ecosystem, map_osv_package_name, supports_osv_query


def _is_prerelease_version(version: str) -> bool:
    return "-" in version


def build_report(
    components: list[Component],
    findings: list[dict[str, Any]],
    advisories_by_component: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    advisory_lookup = advisories_by_component or {}
    coverage = build_scan_coverage(components)
    advisory_coverage = build_advisory_coverage(components, advisory_lookup)
    component_scan_status = build_component_scan_status(components, advisory_lookup, findings)
    grouped_findings = group_findings_by_component(findings)
    intelligence_sources = _build_intelligence_sources(findings)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize_findings(findings),
        "components_scanned": len(components),
        "scan_coverage": coverage,
        "advisory_coverage": advisory_coverage,
        "intelligence_sources": intelligence_sources,
        "component_scan_status": component_scan_status,
        "affected_components": grouped_findings,
        "notes": build_report_notes(components, coverage, advisory_coverage, findings),
        "sbom": export_sbom(components),
        "vulnerabilities": _build_grouped_vulnerabilities(findings),
    }


def build_scan_coverage(components: list[Component]) -> dict[str, Any]:
    ecosystem_counter = Counter(component.ecosystem for component in components)
    type_counter = Counter(component.type for component in components)
    source_counter = Counter(_coverage_source_key(component) for component in components)
    osv_queryable = sum(1 for component in components if supports_osv_query(component))

    return {
        "by_ecosystem": dict(sorted(ecosystem_counter.items())),
        "by_type": dict(sorted(type_counter.items())),
        "by_source": dict(sorted(source_counter.items())),
        "osv_queryable_components": osv_queryable,
        "osv_unqueryable_components": len(components) - osv_queryable,
    }


def build_advisory_coverage(
  components: list[Component],
  advisories_by_component: dict[tuple[str, str], list[dict[str, Any]]],
) -> dict[str, Any]:
  components_with_advisories = 0
  advisories_by_ecosystem: Counter[str] = Counter()
  components_with_advisories_by_ecosystem: Counter[str] = Counter()

  for component in components:
    advisories = advisories_by_component.get((component.name.lower(), component.ecosystem), [])
    if not advisories:
      continue
    components_with_advisories += 1
    advisories_by_ecosystem[component.ecosystem] += len(advisories)
    components_with_advisories_by_ecosystem[component.ecosystem] += 1

  return {
    "components_with_advisories": components_with_advisories,
    "components_without_advisories": len(components) - components_with_advisories,
    "advisories_by_ecosystem": dict(sorted(advisories_by_ecosystem.items())),
    "components_with_advisories_by_ecosystem": dict(sorted(components_with_advisories_by_ecosystem.items())),
    "total_advisories_loaded": sum(advisories_by_ecosystem.values()),
  }


def build_component_scan_status(
  components: list[Component],
  advisories_by_component: dict[tuple[str, str], list[dict[str, Any]]],
  findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
  finding_counts = Counter(_component_key_from_finding(finding) for finding in findings)
  statuses: list[dict[str, Any]] = []

  for component in components:
    key = _component_key(component)
    advisories = advisories_by_component.get((component.name.lower(), component.ecosystem), [])
    queryable = supports_osv_query(component)
    finding_count = finding_counts.get(key, 0)
    status = "unqueryable"
    if queryable:
      status = "queried_no_advisories"
    if advisories:
      status = "advisories_loaded"
    if finding_count:
      status = "matched"

    identity = None
    if queryable:
      identity = {
        "ecosystem": map_osv_ecosystem(component),
        "name": map_osv_package_name(component),
      }

    statuses.append(
      {
        "component": component.to_dict(),
        "query_status": status,
        "query_identity": identity,
        "advisories_loaded": len(advisories),
        "matched_vulnerabilities": finding_count,
      }
    )

  statuses.sort(
    key=lambda item: (
      item["query_status"],
      item["component"]["ecosystem"],
      item["component"]["name"].lower(),
      item["component"]["version"],
    )
  )
  return statuses


def group_findings_by_component(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
  grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

  for finding in findings:
    component = finding.get("component", {})
    key = (
      str(component.get("name", "")).lower(),
      str(component.get("version", "")),
      str(component.get("ecosystem", "")),
    )
    group = grouped.setdefault(
      key,
      {
        "component": component,
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
        "advisory_ids": [],
        "vulnerability_count": 0,
      },
    )
    risk = str(finding.get("final_risk", "UNKNOWN")).lower()
    group["summary"][risk if risk in group["summary"] else "unknown"] += 1
    group["advisory_ids"].append(finding.get("advisory_id", "UNKNOWN"))
    group["vulnerability_count"] += 1

  results = list(grouped.values())
  results.sort(
    key=lambda item: (
      -item["summary"]["critical"],
      -item["summary"]["high"],
      -item["summary"]["medium"],
      item["component"]["name"].lower(),
    )
  )
  return results


def build_report_notes(
    components: list[Component],
    coverage: dict[str, Any],
    advisory_coverage: dict[str, Any],
    findings: list[dict[str, Any]],
) -> list[str]:
    notes: list[str] = []
    by_ecosystem = coverage.get("by_ecosystem", {})
    advisory_counts = advisory_coverage.get("advisories_by_ecosystem", {})

    if by_ecosystem.get("os") and advisory_counts.get("os", 0) == 0:
        notes.append(
            "OS packages were inventoried, but no OS vulnerability advisories were loaded for this scan. On macOS, Homebrew packages are currently inventory-only unless a supported vulnerability mapping is added."
        )
    if by_ecosystem.get("jetbrains"):
        notes.append(
            "JetBrains IDEs are matched against NVD for known CVEs. Individual JetBrains plugins are inventoried but vulnerability matching for plugin artifacts is limited."
        )
    if by_ecosystem.get("vscode") and advisory_counts.get("vscode", 0) == 0:
        notes.append(
            "VS Code extensions were queried through OSV as npm-style packages, but no advisories were returned for the scanned extension package names in this run."
        )
    if findings:
        notes.append(
            "The vulnerabilities array contains one entry per matched advisory. If one component is affected by many advisories, that component will appear repeatedly in the raw findings list. Use affected_components to view grouped results by component."
        )
    else:
        notes.append(
            "No matched vulnerabilities were found. This can mean either the scanned components are not covered by the current advisory sources, or no advisories were returned for their package identifiers."
        )
    return notes


def _coverage_source_key(component: Component) -> str:
    if component.source in {"brew", "dpkg", "rpm"}:
        return component.source
    if component.ecosystem == "vscode":
        return "vscode-extension"
    if component.ecosystem == "jetbrains":
        return "jetbrains-plugin"
    if component.ecosystem == "npm":
        return "project-package"
    return component.source or "unknown"


def _component_key(component: Component) -> tuple[str, str, str]:
    return (component.name.lower(), component.version, component.ecosystem)


def _component_key_from_finding(finding: dict[str, Any]) -> tuple[str, str, str]:
    component = finding.get("component", {})
    return (
        str(component.get("name", "")).lower(),
        str(component.get("version", "")),
        str(component.get("ecosystem", "")),
    )


def _build_grouped_vulnerabilities(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings by component so each component appears only once."""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

    for finding in findings:
        component = finding.get("component", {})
        key = (
            str(component.get("name", "")).lower(),
            str(component.get("version", "")),
            str(component.get("ecosystem", "")),
        )
        if key not in grouped:
            grouped[key] = {
                "component": component,
                "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                "advisories": [],
            }
        group = grouped[key]
        risk = str(finding.get("final_risk", "UNKNOWN")).lower()
        group["severity_summary"][risk if risk in group["severity_summary"] else "unknown"] += 1
        group["advisories"].append({
            "advisory_id": finding.get("advisory_id"),
            "cve": finding.get("cve"),
            "summary": finding.get("summary"),
            "severity": finding.get("severity"),
            "final_risk": finding.get("final_risk"),
            "epss": finding.get("epss"),
            "kev": finding.get("kev"),
            "references": finding.get("references", []),
            "fix_versions": finding.get("fix_versions", []),
            "sources": finding.get("sources", []),
            "source_count": finding.get("source_count", 1),
            "confidence": finding.get("confidence", "low"),
            "cvss_score": finding.get("cvss_score"),
        })

    results = list(grouped.values())
    results.sort(
        key=lambda item: (
            -item["severity_summary"]["critical"],
            -item["severity_summary"]["high"],
            -item["severity_summary"]["medium"],
            item["component"]["name"].lower(),
        )
    )
    return results


def _build_intelligence_sources(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize how many findings came from each intelligence source."""
    source_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    multi_source = 0
    for finding in findings:
        for src in finding.get("sources", []):
            source_counts[src] += 1
        confidence = finding.get("confidence", "low")
        confidence_counts[confidence] += 1
        if finding.get("source_count", 1) >= 2:
            multi_source += 1
    return {
        "sources_used": dict(sorted(source_counts.items())),
        "findings_by_confidence": dict(sorted(confidence_counts.items())),
        "multi_source_findings": multi_source,
        "total_findings": len(findings),
    }


def write_json_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def write_html_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = report.get("summary", {})
    findings = report.get("vulnerabilities", [])
    coverage = report.get("scan_coverage", {})
    advisory_coverage = report.get("advisory_coverage", {})
    intel = report.get("intelligence_sources", {})
    source_coverage = report.get("source_coverage", {})
    notes = report.get("notes", [])
    generated_at = escape(report.get("generated_at", ""))
    components_scanned = report.get("components_scanned", 0)

    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    total = critical + high + medium + low
    sources_used = intel.get("sources_used", {})
    multi_src = intel.get("multi_source_findings", 0)
    total_findings = intel.get("total_findings", 0)

    # Risk score: weighted sum (critical×10, high×5, medium×2, low×0.5) / components
    risk_score = round(
        (critical * 10 + high * 5 + medium * 2 + low * 0.5)
        / max(components_scanned, 1), 1
    )
    risk_grade = "A" if risk_score < 1 else "B" if risk_score < 3 else "C" if risk_score < 6 else "D" if risk_score < 10 else "F"
    risk_color = {"A": "#2e7d32", "B": "#558b2f", "C": "#ca6702", "D": "#bb3e03", "F": "#9b2226"}.get(risk_grade, "#5c6675")

    # Build severity distribution bar percentages
    bar_total = max(total, 1)
    pct_c = round(critical / bar_total * 100, 1)
    pct_h = round(high / bar_total * 100, 1)
    pct_m = round(medium / bar_total * 100, 1)
    pct_l = round(low / bar_total * 100, 1)

    def _domain_for_component(component: dict[str, Any]) -> str:
        ctype = str(component.get("type", "")).lower()
        eco = str(component.get("ecosystem", "")).lower()
        if ctype == "project":
            return "project"
        if eco in {"vscode", "jetbrains"}:
            return "extensions"
        return "system"

    domain_counts_all: Counter[str] = Counter()
    for group in findings:
        domain_counts_all[_domain_for_component(group.get("component", {}))] += len(group.get("advisories", []))

    def _severity_compact(summary_map: dict[str, Any]) -> str:
        return (
            f"C{summary_map.get('critical', 0)} / "
            f"H{summary_map.get('high', 0)} / "
            f"M{summary_map.get('medium', 0)} / "
            f"L{summary_map.get('low', 0)}"
        )

    def _best_fix_version(advisories: list[dict[str, Any]], current_version: str = "") -> str:
        versions: list[str] = []
        for advisory in advisories:
            versions.extend([str(v) for v in advisory.get("fix_versions", []) if v])
        if not versions:
            return "N/A"
        unique_versions = list(dict.fromkeys(versions))
        if not current_version:
            stable_versions = [v for v in unique_versions if not _is_prerelease_version(v)]
            if stable_versions:
                return sorted(stable_versions, key=cmp_to_key(compare_versions))[-1]
            return "N/A"
        newer_candidates = [v for v in unique_versions if compare_versions(v, current_version) > 0]
        if newer_candidates:
            stable_newer = [v for v in newer_candidates if not _is_prerelease_version(v)]
            if stable_newer:
                return sorted(stable_newer, key=cmp_to_key(compare_versions))[0]
        return "N/A"

    # Build top-risk components table
    top_risk_rows = []
    for group in findings:
        c = group.get("component", {})
        domain = _domain_for_component(c)
        s = group.get("severity_summary", {})
        advs = group.get("advisories", [])
        max_cvss = max((a.get("cvss_score") or 0 for a in advs), default=0)
        kev_count = sum(1 for a in advs if a.get("kev"))
        max_epss = max((a.get("epss") or 0 for a in advs), default=0)
        vuln_count = len(advs)
        # Determine row highlight
        if s.get("critical"):
            row_cls = "row-critical"
        elif s.get("high"):
            row_cls = "row-high"
        elif s.get("medium"):
            row_cls = "row-medium"
        else:
            row_cls = ""
        sev_text = _severity_compact(s)
        fix_version = _best_fix_version(advs, str(c.get("version", "")))
        top_risk_rows.append(
            f'<tr class="{row_cls}" data-domain="{domain}" data-has-critical="{1 if s.get("critical", 0) else 0}">'
            f'<td class="comp-name">{escape(c.get("name", ""))}</td>'
            f'<td><code>{escape(c.get("version", ""))}</code></td>'
            f'<td>{escape(domain.title())}</td>'
            f'<td>{vuln_count}</td>'
            f'<td>{escape(sev_text)}</td>'
            f'<td>{max_cvss:.1f}</td>'
            f'<td>{"🔴 " + str(kev_count) if kev_count else "—"}</td>'
            f'<td>{max_epss:.1%}</td>'
            f'<td><code>{escape(fix_version)}</code></td>'
            f'</tr>'
        )

    project_rows = []
    for group in findings:
        c = group.get("component", {})
        if _domain_for_component(c) != "project":
            continue
        advisories = group.get("advisories", [])
        if not advisories:
            continue
        sev = group.get("severity_summary", {})
        project_rows.append(
            f"<tr data-has-critical='{1 if sev.get('critical', 0) else 0}'>"
            f"<td class='comp-name'>{escape(c.get('name', ''))}</td>"
            f"<td><code>{escape(c.get('version', ''))}</code></td>"
            f"<td>{len(advisories)}</td>"
            f"<td>{sev.get('critical', 0)}</td>"
            f"<td>{sev.get('high', 0)}</td>"
            f"<td>{sev.get('medium', 0)}</td>"
            f"<td>{sev.get('low', 0)}</td>"
            f"<td><code>{escape(_best_fix_version(advisories, str(c.get('version', ''))))}</code></td>"
            f"</tr>"
        )

    # Build source contribution data
    source_items = ""
    for src, count in sorted(sources_used.items(), key=lambda x: -x[1]):
        pct = round(count / max(total_findings, 1) * 100)
        source_items += (
            f'<div class="source-bar-row">'
            f'<span class="source-label">{escape(src.upper())}</span>'
            f'<div class="source-bar-track"><div class="source-bar-fill" style="width:{pct}%"></div></div>'
            f'<span class="source-count">{count}</span>'
            f'</div>'
        )
    source_status_items = ""
    for src in ("osv", "nvd", "ghsa", "sonatype"):
        info = source_coverage.get(src, {})
        state = escape(str(info.get("status", "unknown")).upper())
        reason = escape(str(info.get("reason", "")))
        source_status_items += (
            f"<li><strong>{src.upper()}</strong>: {state}"
            f"{' - ' + reason if reason else ''}</li>"
        )

    # Confidence breakdown
    conf = intel.get("findings_by_confidence", {})
    conf_high = conf.get("high", 0)
    conf_med = conf.get("medium", 0)
    conf_low_c = conf.get("low", 0)

    # Notes
    notes_html = "".join(f'<li>{escape(n)}</li>' for n in notes) if notes else '<li>No additional notes.</li>'

    # Build ecosystem breakdown
    eco_counter: Counter[str] = Counter()
    for group in findings:
        eco = group.get("component", {}).get("ecosystem", "unknown")
        eco_counter[eco] += len(group.get("advisories", []))
    eco_items = ""
    for eco, cnt in eco_counter.most_common():
        eco_items += f'<div class="eco-chip"><strong>{cnt}</strong> {escape(eco)}</div>'

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Supply Chain Security Report</title>
<style>
:root {{
  --bg:#09090b; --surface:#18181b; --surface2:#27272a;
  --border:#3f3f46; --text:#fafafa; --muted:#a1a1aa;
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#22d3ee;
  --green:#22c55e; --blue:#3b82f6;
  --radius:12px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text);padding:24px;line-height:1.5}}
.container{{max-width:1200px;margin:0 auto}}
h1{{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em}}
h2{{font-size:1.1rem;font-weight:600;margin-bottom:12px;color:var(--muted)}}
h3{{font-size:0.95rem;font-weight:600;margin-bottom:8px}}

/* Header */
.header{{display:flex;justify-content:space-between;align-items:center;
  padding:20px 24px;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);margin-bottom:20px;flex-wrap:wrap;gap:12px}}
.header-meta{{color:var(--muted);font-size:0.82rem}}

/* Grid */
.grid{{display:grid;gap:16px;margin-bottom:20px}}
.grid-4{{grid-template-columns:repeat(4,1fr)}}
.grid-3{{grid-template-columns:repeat(3,1fr)}}
.grid-2{{grid-template-columns:1fr 1fr}}
@media(max-width:900px){{.grid-4,.grid-3{{grid-template-columns:repeat(2,1fr)}}}}
@media(max-width:600px){{.grid-4,.grid-3,.grid-2{{grid-template-columns:1fr}}}}

/* Cards */
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px}}
.card-sm{{padding:16px}}

/* Metric Cards */
.metric{{text-align:center}}
.metric .value{{font-size:2.2rem;font-weight:800;line-height:1}}
.metric .label{{font-size:0.78rem;color:var(--muted);text-transform:uppercase;
  letter-spacing:0.06em;margin-top:6px}}

/* Risk Grade */
.grade-ring{{width:100px;height:100px;border-radius:50%;
  border:6px solid {risk_color};display:flex;align-items:center;justify-content:center;
  margin:0 auto 8px}}
.grade-ring .letter{{font-size:2.4rem;font-weight:800;color:{risk_color}}}

/* Severity bar */
.sev-bar{{display:flex;height:14px;border-radius:99px;overflow:hidden;margin:8px 0}}
.sev-bar div{{height:100%;min-width:2px}}
.sev-bar .bar-c{{background:var(--critical)}}
.sev-bar .bar-h{{background:var(--high)}}
.sev-bar .bar-m{{background:var(--medium)}}
.sev-bar .bar-l{{background:var(--low)}}

.sev-legend{{display:flex;gap:14px;flex-wrap:wrap;font-size:0.8rem;color:var(--muted)}}
.sev-legend span::before{{content:'';display:inline-block;width:10px;height:10px;
  border-radius:3px;margin-right:4px;vertical-align:middle}}
.sev-legend .leg-c::before{{background:var(--critical)}}
.sev-legend .leg-h::before{{background:var(--high)}}
.sev-legend .leg-m::before{{background:var(--medium)}}
.sev-legend .leg-l::before{{background:var(--low)}}

/* Source bars */
.source-bar-row{{display:flex;align-items:center;gap:8px;margin-bottom:8px}}
.source-label{{width:80px;font-size:0.78rem;font-weight:700;color:var(--muted);
  text-transform:uppercase;letter-spacing:0.04em;text-align:right}}
.source-bar-track{{flex:1;height:8px;background:var(--surface2);border-radius:99px;overflow:hidden}}
.source-bar-fill{{height:100%;background:var(--blue);border-radius:99px;
  transition:width 0.4s ease}}
.source-count{{font-size:0.82rem;width:40px;color:var(--muted)}}

/* Confidence */
.conf-row{{display:flex;gap:12px;margin-top:10px}}
.conf-chip{{font-size:0.82rem;padding:4px 12px;border-radius:99px;font-weight:600}}
.conf-high{{background:rgba(34,197,94,0.15);color:var(--green)}}
.conf-med{{background:rgba(234,179,8,0.15);color:var(--medium)}}
.conf-low{{background:rgba(161,161,170,0.1);color:var(--muted)}}

/* Table */
table{{width:100%;border-collapse:collapse}}
th{{font-size:0.72rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);
  padding:10px 12px;text-align:left;border-bottom:1px solid var(--border);font-weight:600}}
td{{padding:10px 12px;border-bottom:1px solid var(--border);font-size:0.88rem}}
tr:hover{{background:rgba(255,255,255,0.03)}}
.row-critical td:first-child{{border-left:3px solid var(--critical);padding-left:9px}}
.row-high td:first-child{{border-left:3px solid var(--high);padding-left:9px}}
.row-medium td:first-child{{border-left:3px solid var(--medium);padding-left:9px}}
.comp-name{{font-weight:600}}
code{{font-size:0.82rem;background:var(--surface2);padding:2px 6px;border-radius:4px}}

/* Pills */
.pill{{font-size:0.7rem;font-weight:700;padding:2px 8px;border-radius:99px;
  display:inline-block;margin-right:3px}}
.pill.critical{{background:rgba(239,68,68,0.15);color:var(--critical)}}
.pill.high{{background:rgba(249,115,22,0.15);color:var(--high)}}
.pill.medium{{background:rgba(234,179,8,0.15);color:var(--medium)}}
.pill.low{{background:rgba(34,211,238,0.15);color:var(--low)}}

/* Eco chips */
.eco-chips{{display:flex;flex-wrap:wrap;gap:8px}}
.eco-chip{{background:var(--surface2);padding:6px 14px;border-radius:99px;font-size:0.82rem;color:var(--muted)}}
.eco-chip strong{{color:var(--text);margin-right:4px}}
.domain-tabs{{display:flex;gap:8px;margin:10px 0 12px;flex-wrap:wrap}}
.domain-tab{{background:var(--surface2);border:1px solid var(--border);color:var(--muted);
  padding:6px 12px;border-radius:999px;font-size:0.78rem;cursor:pointer}}
.domain-tab.active{{color:var(--text);border-color:var(--blue)}}
.toggle-critical{{margin-top:8px;display:flex;align-items:center;gap:8px;color:var(--muted);font-size:0.8rem}}

/* Notes */
.notes ul{{padding-left:20px;color:var(--muted);font-size:0.85rem}}
.notes li{{margin-bottom:6px}}

/* Footer */
.footer{{text-align:center;color:var(--muted);font-size:0.75rem;margin-top:32px;padding:16px}}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div>
      <h1>🛡️ Supply Chain Security Report</h1>
      <div class="header-meta">{generated_at} · {components_scanned} components scanned</div>
    </div>
    <div style="text-align:right">
      <div class="header-meta">Sources: {escape(', '.join(sorted(sources_used.keys())).upper())}</div>
      <div class="header-meta">{total_findings} findings · {multi_src} multi-source confirmed</div>
    </div>
  </div>

  <!-- Top Metrics -->
  <div class="grid grid-4" style="margin-bottom:20px">
    <div class="card card-sm metric">
      <div class="value" style="color:var(--critical)">{critical}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card card-sm metric">
      <div class="value" style="color:var(--high)">{high}</div>
      <div class="label">High</div>
    </div>
    <div class="card card-sm metric">
      <div class="value" style="color:var(--medium)">{medium}</div>
      <div class="label">Medium</div>
    </div>
    <div class="card card-sm metric">
      <div class="value" style="color:var(--low)">{low}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <!-- Risk + Distribution + Sources row -->
  <div class="grid grid-3">
    <!-- Risk Grade -->
    <div class="card" style="text-align:center">
      <h2>Risk Grade</h2>
      <div class="grade-ring"><span class="letter">{risk_grade}</span></div>
      <div style="font-size:0.85rem;color:var(--muted)">Score: {risk_score} / component</div>
    </div>

    <!-- Severity Distribution -->
    <div class="card">
      <h2>Severity Distribution</h2>
      <div class="sev-bar">
        <div class="bar-c" style="width:{pct_c}%"></div>
        <div class="bar-h" style="width:{pct_h}%"></div>
        <div class="bar-m" style="width:{pct_m}%"></div>
        <div class="bar-l" style="width:{pct_l}%"></div>
      </div>
      <div class="sev-legend">
        <span class="leg-c">Critical {critical}</span>
        <span class="leg-h">High {high}</span>
        <span class="leg-m">Medium {medium}</span>
        <span class="leg-l">Low {low}</span>
      </div>
      <div style="margin-top:14px;font-size:0.82rem;color:var(--muted)">
        Affected: <strong style="color:var(--text)">{len(findings)}</strong> components of {components_scanned}
      </div>
    </div>

    <!-- Intelligence Sources -->
    <div class="card">
      <h2>Intelligence Sources</h2>
      {source_items}
      <ul style="margin-top:10px;padding-left:18px;color:var(--muted);font-size:0.78rem">{source_status_items}</ul>
      <div class="conf-row">
        <span class="conf-chip conf-high">✓ {conf_high} high</span>
        <span class="conf-chip conf-med">~ {conf_med} medium</span>
        <span class="conf-chip conf-low">? {conf_low_c} low</span>
      </div>
    </div>
  </div>

  <!-- Top Risk Components -->
  <div class="card" style="margin-top:20px">
    <h2>🔥 Top Risk Components</h2>
    <div class="domain-tabs">
      <button class="domain-tab active" data-domain="all">All ({sum(domain_counts_all.values())})</button>
      <button class="domain-tab" data-domain="project">Project ({domain_counts_all.get("project", 0)})</button>
      <button class="domain-tab" data-domain="system">System ({domain_counts_all.get("system", 0)})</button>
      <button class="domain-tab" data-domain="extensions">Extensions ({domain_counts_all.get("extensions", 0)})</button>
    </div>
    <label class="toggle-critical">
      <input id="criticalOnlyToggle" type="checkbox" />
      Show critical-only rows
    </label>
    <table>
      <thead>
        <tr>
          <th>Component</th><th>Version</th><th>Domain</th><th>Vulns</th><th>Severity</th>
          <th>Max CVSS</th><th>KEV</th><th>Max EPSS</th><th>Fix Version</th>
        </tr>
      </thead>
      <tbody>{''.join(top_risk_rows)}</tbody>
    </table>
  </div>

  <div class="card" style="margin-top:20px">
    <h2>📦 Project Vulnerabilities</h2>
    <label class="toggle-critical">
      <input id="projectCriticalOnlyToggle" type="checkbox" />
      Show critical-only project packages
    </label>
    <table>
      <thead>
        <tr>
          <th>Package</th><th>Version</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
          <th>Fix Version</th>
        </tr>
      </thead>
      <tbody>{''.join(project_rows) or "<tr><td colspan='8'>No project vulnerabilities found for selected path.</td></tr>"}</tbody>
    </table>
  </div>

  <!-- Ecosystem breakdown -->
  <div class="grid grid-2" style="margin-top:20px">
    <div class="card">
      <h2>Findings by Ecosystem</h2>
      <div class="eco-chips">{eco_items or '<span class="eco-chip">No data</span>'}</div>
    </div>
    <div class="card notes">
      <h2>Notes</h2>
      <ul>{notes_html}</ul>
    </div>
  </div>

  <div class="footer">
    Supply Chain Scanner · Local-first vulnerability intelligence · {escape(generated_at)}
  </div>
</div>
<script>
(function(){{
  const tabs=document.querySelectorAll('.domain-tab');
  const rows=document.querySelectorAll('tbody tr[data-domain]');
  const criticalOnlyToggle=document.getElementById('criticalOnlyToggle');
  const projectCriticalOnlyToggle=document.getElementById('projectCriticalOnlyToggle');
  const projectRows=document.querySelectorAll("div.card table tbody tr[data-has-critical]");
  let criticalOnly=false;
  function applyDomainAndCritical(){{
    const active=document.querySelector('.domain-tab.active');
    const domain=active?active.dataset.domain:'all';
    rows.forEach(row=>{{
      const domainMatch=domain==='all'||row.dataset.domain===domain;
      const criticalMatch=!criticalOnly||row.dataset.hasCritical==='1';
      row.style.display=(domainMatch&&criticalMatch)?'table-row':'none';
    }});
  }}
  tabs.forEach(tab=>{{
    tab.addEventListener('click',()=>{{
      tabs.forEach(t=>t.classList.remove('active'));
      tab.classList.add('active');
      applyDomainAndCritical();
    }});
  }});
  if(criticalOnlyToggle){{
    criticalOnlyToggle.addEventListener('change',()=>{{
      criticalOnly=criticalOnlyToggle.checked;
      applyDomainAndCritical();
    }});
  }}
  if(projectCriticalOnlyToggle){{
    projectCriticalOnlyToggle.addEventListener('change',()=>{{
      const enabled=projectCriticalOnlyToggle.checked;
      projectRows.forEach(row=>{{
        const keep=!enabled||row.dataset.hasCritical==='1';
        row.style.display=keep?'table-row':'none';
      }});
    }});
  }}
  applyDomainAndCritical();
}})();
</script>
</body>
</html>""".strip()

    path.write_text(html, encoding="utf-8")
    return path


def _source_badges_html(advisory: dict[str, Any]) -> str:
    """Generate HTML source/confidence badges for an advisory."""
    sources = advisory.get("sources", [])
    confidence = advisory.get("confidence", "low")
    if not sources:
        return ""
    src_html = " ".join(
        f'<span class="badge-source">{escape(s.upper())}</span>'
        for s in sources
    )
    conf_class = {"high": "confidence-high", "medium": "confidence-medium"}.get(confidence, "confidence-low")
    conf_label = f'{len(sources)} source{"s" if len(sources) != 1 else ""}'
    return f'{src_html} <span class="badge-confidence {conf_class}">{escape(conf_label)}</span>'


def _component_remediation(component: dict[str, Any], advisories: list[dict[str, Any]]) -> tuple[str, str | None]:
    ecosystem = str(component.get("ecosystem", "")).lower()
    name = str(component.get("name", ""))
    metadata = component.get("metadata", {}) or {}
    fix_versions = list({str(v) for adv in advisories for v in adv.get("fix_versions", []) if v})
    current_version = str(component.get("version", ""))
    newer_fixes = [v for v in fix_versions if current_version and compare_versions(v, current_version) > 0]
    if newer_fixes:
        stable_newer = [v for v in newer_fixes if not _is_prerelease_version(v)]
        if stable_newer:
            target_fix = sorted(stable_newer, key=cmp_to_key(compare_versions))[0]
        else:
            target_fix = ""
    else:
        target_fix = ""
    source = str(component.get("source", "")).lower()
    package_manager = str(metadata.get("package_manager", "")).lower()

    if ecosystem in {"npm", "vscode"}:
        if target_fix:
            return f"npm install {name}@{target_fix}", f"https://www.npmjs.com/package/{name}"
        return f"npm update {name}", f"https://www.npmjs.com/package/{name}"
    if ecosystem == "nuget":
        if target_fix:
            return f"dotnet add package {name} --version {target_fix}", f"https://www.nuget.org/packages/{name}"
        return f"dotnet list package --outdated | grep {name}", f"https://www.nuget.org/packages/{name}"
    if ecosystem == "maven":
        if target_fix:
            return f"mvn versions:use-dep-version -Dincludes={name} -DdepVersion={target_fix}", None
        return f"mvn versions:display-dependency-updates | grep {name}", None
    if ecosystem == "os":
        if package_manager == "brew" or source == "brew":
            pkg_kind = str(metadata.get("package_kind", "")).lower()
            if pkg_kind == "cask":
                return f"brew upgrade --cask {name}", "https://formulae.brew.sh/cask/"
            return f"brew upgrade {name}", f"https://formulae.brew.sh/formula/{name}"
        if package_manager == "winget" or source == "winget":
            pkg_id = str(metadata.get("package_id", "")).strip()
            if pkg_id:
                return f"winget upgrade --id {pkg_id}", "https://winget.run/"
            return f"winget upgrade {name}", "https://winget.run/"
        if package_manager == "chocolatey" or source == "chocolatey":
            return f"choco upgrade {name} -y", f"https://community.chocolatey.org/packages/{name}"
        if package_manager == "app_bundle":
            return f"Open vendor updater for {name}", _app_download_link(name)
    if ecosystem == "jetbrains":
        return f"Update from JetBrains Toolbox / IDE Plugin Manager for {name}", "https://www.jetbrains.com/toolbox-app/"
    return "Review vendor advisory and update to latest secure version", None


def _app_download_link(name: str) -> str | None:
    mapping = {
        "Google Chrome": "https://www.google.com/chrome/",
        "Chromium": "https://www.chromium.org/getting-involved/download-chromium/",
        "Firefox": "https://www.mozilla.org/firefox/new/",
        "Microsoft Edge": "https://www.microsoft.com/edge/download",
        "Brave Browser": "https://brave.com/download/",
        "Visual Studio Code": "https://code.visualstudio.com/Download",
        "Docker Desktop": "https://www.docker.com/products/docker-desktop/",
        "Postman": "https://www.postman.com/downloads/",
    }
    return mapping.get(name)


def write_vuln_fixes_html_report(report: dict[str, Any], output_path: str | Path) -> Path:
    """Write an HTML report focused on vulnerabilities, risk details, and fixes."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = report.get("summary", {})
    vuln_groups = report.get("vulnerabilities", [])
    intel = report.get("intelligence_sources", {})
    generated_at = escape(report.get("generated_at", ""))
    components_scanned = report.get("components_scanned", 0)

    total_vulns = sum(len(g.get("advisories", [])) for g in vuln_groups)
    total_components = len(vuln_groups)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    multi_src = intel.get("multi_source_findings", 0)

    # Collect all advisories with EPSS > 0 for the risk scatter data
    scatter_data = []
    for group in vuln_groups:
        comp = group.get("component", {})
        for adv in group.get("advisories", []):
            cvss = adv.get("cvss_score") or 0
            epss = adv.get("epss") or 0
            if cvss > 0 or epss > 0:
                scatter_data.append({
                    "name": comp.get("name", ""),
                    "id": adv.get("advisory_id") or adv.get("cve") or "",
                    "cvss": cvss,
                    "epss": round(epss * 100, 2),
                    "sev": (adv.get("final_risk") or "UNKNOWN").lower(),
                    "kev": adv.get("kev", False),
                })
    # Sort by risk (CVSS * EPSS combined)
    scatter_data.sort(key=lambda d: -(d["cvss"] * d["epss"]))
    top_scatter = scatter_data[:80]

    # Build scatter dots via pure CSS
    scatter_dots = ""
    for d in top_scatter:
        left = round(d["epss"] / max(100, 1) * 100, 1)  # epss is 0-100 already
        bottom = round(d["cvss"] / 10 * 100, 1)
        sev_cls = d["sev"] if d["sev"] in ("critical", "high", "medium", "low") else "unknown"
        size = "10" if d["kev"] else "7"
        tip = escape(f'{d["id"]}: CVSS {d["cvss"]}, EPSS {d["epss"]}%')
        scatter_dots += (
            f'<div class="dot {sev_cls}" style="left:{left}%;bottom:{bottom}%;'
            f'width:{size}px;height:{size}px" title="{tip}"></div>'
        )

    # Build component cards
    cards = []
    for group in vuln_groups:
        component = group.get("component", {})
        advisories = group.get("advisories", [])
        sev_summary = group.get("severity_summary", {})
        comp_name = escape(component.get("name", ""))
        comp_ver = escape(component.get("version", ""))
        comp_eco = escape(component.get("ecosystem", ""))
        remediation_cmd, remediation_link = _component_remediation(component, advisories)
        link_html = ""
        if remediation_link:
            safe_link = escape(remediation_link)
            link_html = f'<a class="download-link" href="{safe_link}" target="_blank" rel="noopener noreferrer">Download update</a>'
        remediation_html = (
            f'<div class="remediation"><div class="rem-title">Recommended fix action</div>'
            f'<code class="rem-cmd">{escape(remediation_cmd)}</code>'
            f'<button class="copy-btn" data-copy="{escape(remediation_cmd)}">Copy command</button>'
            f"{link_html}"
            f"</div>"
        )

        if sev_summary.get("critical"):
            card_accent = "var(--critical)"
        elif sev_summary.get("high"):
            card_accent = "var(--high)"
        elif sev_summary.get("medium"):
            card_accent = "var(--medium)"
        elif sev_summary.get("low"):
            card_accent = "var(--low)"
        else:
            card_accent = "var(--border)"

        # Severity pills
        sev_pills = ""
        for lv, cnt in [("critical", sev_summary.get("critical", 0)),
                         ("high", sev_summary.get("high", 0)),
                         ("medium", sev_summary.get("medium", 0)),
                         ("low", sev_summary.get("low", 0)),
                         ("unknown", sev_summary.get("unknown", 0))]:
            if cnt:
                sev_pills += f'<span class="pill {lv}">{cnt} {lv.upper()}</span>'

        # Advisory rows
        adv_items = []
        for adv in advisories:
            adv_id = escape(adv.get("advisory_id") or "")
            cve = escape(adv.get("cve") or "")
            adv_summary = escape(adv.get("summary") or "No description available.")
            # Truncate long summaries
            if len(adv_summary) > 300:
                adv_summary = adv_summary[:297] + "..."
            sev = (adv.get("final_risk") or "UNKNOWN").lower()
            sev_class = sev if sev in ("critical", "high", "medium", "low") else "unknown"
            cvss = adv.get("cvss_score")
            cvss_html = f'<span class="cvss-badge">{cvss:.1f}</span>' if cvss else ''
            epss_val = adv.get("epss")
            epss_html = f'<span class="epss-val">{epss_val:.1%}</span>' if epss_val else '<span class="epss-val dim">—</span>'
            kev_html = '<span class="kev-badge">⚠ KEV</span>' if adv.get("kev") else ''

            # Sources & confidence
            sources = adv.get("sources", [])
            confidence = adv.get("confidence", "low")
            src_html = " ".join(f'<span class="src-tag">{escape(s)}</span>' for s in sources)
            conf_cls = {"high": "conf-high", "medium": "conf-med"}.get(confidence, "conf-low")
            conf_label = f'{len(sources)} source{"s" if len(sources) != 1 else ""}'

            # Fix versions
            fix_versions = adv.get("fix_versions", [])
            if fix_versions:
                fix_html = '<div class="fix-box">' + "".join(
                    f'<code>{escape(v)}</code>' for v in fix_versions
                ) + '</div>'
            else:
                fix_html = '<div class="fix-box no-fix">No fix available</div>'

            # Reference link
            ref_html = ""
            for ref in adv.get("references", []):
                url = ref.get("url", "")
                if url:
                    ref_html = f'<a href="{escape(url)}" target="_blank" rel="noopener noreferrer" class="ref-link">↗ Details</a>'
                    break

            adv_items.append(f"""
            <div class="adv-row" data-sev="{sev_class}">
              <div class="adv-top">
                <div class="adv-id-group">
                  <span class="pill {sev_class}" style="font-size:0.72rem">{sev.upper()}</span>
                  <span class="adv-id">{adv_id}</span>
                  {f'<span class="cve-tag">{cve}</span>' if cve else ''}
                  {cvss_html}
                  {kev_html}
                </div>
                <div class="adv-meta">
                  {epss_html}
                  {src_html}
                  <span class="conf-tag {conf_cls}">{escape(conf_label)}</span>
                  {ref_html}
                </div>
              </div>
              <p class="adv-desc">{adv_summary}</p>
              {fix_html}
            </div>""")

        cards.append(f"""
    <div class="comp-card" style="border-left-color:{card_accent}">
      <div class="comp-header">
        <div>
          <span class="comp-name">{comp_name}</span>
          <code class="comp-ver">{comp_ver}</code>
          <span class="eco-tag">{comp_eco}</span>
        </div>
        <div class="comp-pills">{sev_pills}</div>
      </div>
      {remediation_html}
      <div class="adv-list">{''.join(adv_items)}</div>
    </div>""")

    # Filter buttons with count badges
    filter_btns = f"""
    <div class="filter-bar">
      <button class="fbtn active" data-sev="all">All <span class="fbtn-count">{total_vulns}</span></button>
      <button class="fbtn" data-sev="critical" style="--ac:var(--critical)">Critical <span class="fbtn-count">{critical}</span></button>
      <button class="fbtn" data-sev="high" style="--ac:var(--high)">High <span class="fbtn-count">{high}</span></button>
      <button class="fbtn" data-sev="medium" style="--ac:var(--medium)">Medium <span class="fbtn-count">{medium}</span></button>
      <button class="fbtn" data-sev="low" style="--ac:var(--low)">Low <span class="fbtn-count">{low}</span></button>
    </div>"""

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerabilities &amp; Risk Report</title>
<style>
:root {{
  --bg:#09090b; --surface:#18181b; --surface2:#27272a;
  --border:#3f3f46; --text:#fafafa; --muted:#a1a1aa;
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#22d3ee;
  --green:#22c55e; --blue:#3b82f6; --radius:12px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text);padding:24px;line-height:1.5}}
.container{{max-width:1060px;margin:0 auto}}

/* Header */
.hdr{{padding:20px 24px;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);margin-bottom:20px;
  display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}
.hdr h1{{font-size:1.4rem;font-weight:700;letter-spacing:-0.02em}}
.hdr-meta{{color:var(--muted);font-size:0.8rem}}

/* Summary strip */
.strip{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px}}
@media(max-width:700px){{.strip{{grid-template-columns:repeat(3,1fr)}}}}
.scard{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:14px;text-align:center}}
.scard .sv{{font-size:1.8rem;font-weight:800;line-height:1}}
.scard .sl{{font-size:0.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;margin-top:4px}}

/* Scatter plot */
.scatter-wrap{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;margin-bottom:20px}}
.scatter-wrap h2{{font-size:1rem;font-weight:600;margin-bottom:14px;color:var(--muted)}}
.scatter{{position:relative;width:100%;height:260px;border-left:1px solid var(--border);
  border-bottom:1px solid var(--border)}}
.scatter .axis-x{{position:absolute;bottom:-22px;width:100%;display:flex;
  justify-content:space-between;font-size:0.68rem;color:var(--muted)}}
.scatter .axis-y{{position:absolute;left:-30px;height:100%;display:flex;flex-direction:column-reverse;
  justify-content:space-between;font-size:0.68rem;color:var(--muted)}}
.scatter .axis-label-x{{position:absolute;bottom:-38px;left:50%;transform:translateX(-50%);
  font-size:0.72rem;color:var(--muted)}}
.scatter .axis-label-y{{position:absolute;left:-52px;top:50%;transform:translateY(-50%) rotate(-90deg);
  font-size:0.72rem;color:var(--muted);white-space:nowrap}}
.dot{{position:absolute;border-radius:50%;opacity:0.85;cursor:default;z-index:1}}
.dot.critical{{background:var(--critical)}}
.dot.high{{background:var(--high)}}
.dot.medium{{background:var(--medium)}}
.dot.low{{background:var(--low)}}
.dot.unknown{{background:var(--muted)}}
.scatter .quadrant{{position:absolute;right:0;top:0;width:50%;height:40%;
  background:rgba(239,68,68,0.04);border-radius:0 0 0 8px;
  display:flex;align-items:flex-start;justify-content:flex-end;
  padding:6px 8px;font-size:0.68rem;color:rgba(239,68,68,0.5);pointer-events:none}}

/* Filter */
.filter-bar{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}}
.fbtn{{background:var(--surface);border:1px solid var(--border);color:var(--muted);
  padding:6px 16px;border-radius:99px;cursor:pointer;font-size:0.82rem;
  font-weight:600;transition:all 0.15s}}
.fbtn:hover,.fbtn.active{{background:var(--surface2);color:var(--text);border-color:var(--ac,var(--border))}}
.fbtn.active{{box-shadow:0 0 0 1px var(--ac,var(--border))}}
.fbtn-count{{font-size:0.7rem;background:var(--surface2);padding:1px 7px;border-radius:99px;margin-left:4px;font-weight:700}}
.fbtn.active .fbtn-count{{background:rgba(255,255,255,0.1)}}
.adv-row.hidden{{display:none}}
.comp-card.hidden{{display:none}}

/* Component cards */
.comp-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;margin-bottom:14px;border-left:4px solid var(--border)}}
.comp-header{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px}}
.comp-name{{font-weight:700;font-size:1.05rem}}
.comp-ver{{font-size:0.82rem;background:var(--surface2);padding:2px 8px;border-radius:4px;margin:0 6px}}
.eco-tag{{font-size:0.72rem;color:var(--muted);background:var(--surface2);
  padding:2px 10px;border-radius:99px}}
.comp-pills{{display:flex;gap:4px;flex-wrap:wrap}}

/* Pills */
.pill{{font-size:0.72rem;font-weight:700;padding:3px 10px;border-radius:99px;display:inline-block}}
.pill.critical{{background:rgba(239,68,68,0.15);color:var(--critical)}}
.pill.high{{background:rgba(249,115,22,0.15);color:var(--high)}}
.pill.medium{{background:rgba(234,179,8,0.15);color:var(--medium)}}
.pill.low{{background:rgba(34,211,238,0.15);color:var(--low)}}
.pill.unknown{{background:rgba(161,161,170,0.1);color:var(--muted)}}

/* Advisory rows */
.adv-list{{display:flex;flex-direction:column;gap:0}}
.adv-row{{padding:14px 0;border-top:1px solid var(--border)}}
.adv-row:first-child{{border-top:none;padding-top:0}}
.adv-top{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}}
.adv-id-group{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.adv-id{{font-weight:600;font-family:monospace;font-size:0.88rem}}
.cve-tag{{font-size:0.75rem;color:var(--muted);font-family:monospace;
  background:var(--surface2);padding:2px 8px;border-radius:4px}}
.cvss-badge{{font-size:0.72rem;font-weight:700;background:rgba(249,115,22,0.15);
  color:var(--high);padding:2px 8px;border-radius:4px;font-family:monospace}}
.kev-badge{{font-size:0.72rem;font-weight:700;background:rgba(239,68,68,0.2);
  color:var(--critical);padding:2px 8px;border-radius:4px}}
.adv-meta{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.epss-val{{font-size:0.78rem;color:var(--muted);font-family:monospace}}
.epss-val.dim{{opacity:0.4}}
.src-tag{{font-size:0.65rem;padding:2px 7px;border-radius:6px;
  background:rgba(59,130,246,0.12);color:var(--blue);font-weight:700;
  text-transform:uppercase;letter-spacing:0.03em}}
.conf-tag{{font-size:0.65rem;padding:2px 8px;border-radius:6px;font-weight:600}}
.conf-high{{background:rgba(34,197,94,0.15);color:var(--green)}}
.conf-med{{background:rgba(234,179,8,0.12);color:var(--medium)}}
.conf-low{{background:rgba(161,161,170,0.08);color:var(--muted)}}
.ref-link{{font-size:0.78rem;color:var(--blue);text-decoration:none;font-weight:600}}
.ref-link:hover{{text-decoration:underline}}
.adv-desc{{color:var(--muted);font-size:0.84rem;margin:8px 0;line-height:1.5}}
.fix-box{{font-size:0.82rem;margin-top:8px;padding:8px 14px;border-radius:8px;
  background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.15)}}
.fix-box code{{background:rgba(34,197,94,0.15);color:var(--green);padding:2px 8px;
  border-radius:4px;font-size:0.8rem;margin-right:6px}}
.fix-box.no-fix{{color:var(--muted);background:var(--surface2);border-color:var(--border)}}
.remediation{{margin:8px 0 10px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--surface2)}}
.rem-title{{font-size:0.75rem;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em}}
.rem-cmd{{display:block;padding:6px 8px;border-radius:6px;background:#111827;color:#a7f3d0;font-size:0.8rem;white-space:pre-wrap}}
.copy-btn,.download-link{{margin-top:8px;display:inline-block;font-size:0.76rem;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);text-decoration:none;cursor:pointer}}
.download-link{{margin-left:8px}}

.footer{{text-align:center;color:var(--muted);font-size:0.75rem;margin-top:32px;padding:16px}}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="hdr">
    <div>
      <h1>⚡ Vulnerabilities &amp; Risk</h1>
      <div class="hdr-meta">{generated_at}</div>
    </div>
    <div style="text-align:right">
      <div class="hdr-meta">{components_scanned} scanned · {total_components} affected · {total_vulns} findings</div>
      <div class="hdr-meta">{multi_src} multi-source confirmed</div>
    </div>
  </div>

  <!-- Summary -->
  <div class="strip">
    <div class="scard"><div class="sv" style="color:var(--critical)">{critical}</div><div class="sl">Critical</div></div>
    <div class="scard"><div class="sv" style="color:var(--high)">{high}</div><div class="sl">High</div></div>
    <div class="scard"><div class="sv" style="color:var(--medium)">{medium}</div><div class="sl">Medium</div></div>
    <div class="scard"><div class="sv" style="color:var(--low)">{low}</div><div class="sl">Low</div></div>
    <div class="scard"><div class="sv">{total_components}</div><div class="sl">Components</div></div>
    <div class="scard"><div class="sv">{total_vulns}</div><div class="sl">Total</div></div>
  </div>

  <!-- CVSS vs EPSS Scatter -->
  <div class="scatter-wrap">
    <h2>CVSS vs EPSS — Risk Heatmap</h2>
    <div class="scatter">
      <div class="quadrant">HIGH RISK ZONE</div>
      {scatter_dots}
      <div class="axis-x"><span>0%</span><span>25%</span><span>50%</span><span>75%</span><span>100%</span></div>
      <div class="axis-y"><span>0</span><span>2.5</span><span>5</span><span>7.5</span><span>10</span></div>
      <div class="axis-label-x">EPSS (Exploit Probability)</div>
      <div class="axis-label-y">CVSS Score</div>
    </div>
  </div>

  <!-- Filter -->
  {filter_btns}

  <!-- Vulnerability Cards -->
  {''.join(cards) or '<div class="comp-card"><p style="color:var(--muted)">No vulnerabilities found.</p></div>'}

  <div class="footer">Supply Chain Scanner · {escape(generated_at)}</div>
</div>
<script>
(function(){{
  const btns=document.querySelectorAll('.fbtn');
  const cards=document.querySelectorAll('.comp-card');
  const rows=document.querySelectorAll('.adv-row');
  btns.forEach(btn=>{{
    btn.addEventListener('click',()=>{{
      btns.forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      const sev=btn.dataset.sev;
      /* filter individual advisory rows */
      rows.forEach(r=>{{
        if(sev==='all'){{r.classList.remove('hidden');return}}
        r.classList.toggle('hidden',r.dataset.sev!==sev);
      }});
      /* hide cards that have zero visible rows */
      cards.forEach(card=>{{
        if(sev==='all'){{card.classList.remove('hidden');return}}
        const visible=card.querySelectorAll('.adv-row:not(.hidden)');
        card.classList.toggle('hidden',visible.length===0);
      }});
    }});
  }});
}})();
document.querySelectorAll('.copy-btn').forEach((btn)=>{{
  btn.addEventListener('click', async () => {{
    const text = btn.getAttribute('data-copy') || '';
    try {{
      await navigator.clipboard.writeText(text);
      btn.textContent='Copied';
      setTimeout(()=>btn.textContent='Copy command',1200);
    }} catch (_e) {{}}
  }});
}});
</script>
</body>
</html>""".strip()

    path.write_text(html, encoding="utf-8")
    return path


def write_epss_remediation_html_report(report: dict[str, Any], output_path: str | Path) -> Path:
    """Write a ranked remediation report prioritizing exploitability."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    vuln_groups = report.get("vulnerabilities", [])
    generated_at = escape(report.get("generated_at", ""))

    rows: list[dict[str, Any]] = []
    for group in vuln_groups:
        component = group.get("component", {})
        advisories = group.get("advisories", [])
        command, download = _component_remediation(component, advisories)
        for advisory in advisories:
            final_risk = str(advisory.get("final_risk", "UNKNOWN")).upper()
            epss = float(advisory.get("epss") or 0.0)
            kev = bool(advisory.get("kev"))
            cvss = float(advisory.get("cvss_score") or 0.0)
            priority_score = (
                (1000 if kev else 0)
                + (100 if final_risk == "CRITICAL" else 0)
                + (60 if final_risk == "HIGH" else 0)
                + (25 if final_risk == "MEDIUM" else 0)
                + int(epss * 1000)
                + int(cvss * 10)
            )
            if kev or epss >= 0.2 or final_risk == "CRITICAL":
                bucket = "Immediate"
            elif epss >= 0.05 or final_risk == "HIGH":
                bucket = "72h"
            elif final_risk == "MEDIUM":
                bucket = "7d"
            else:
                bucket = "Backlog"
            rows.append(
                {
                    "component": component,
                    "advisory": advisory,
                    "epss": epss,
                    "kev": kev,
                    "cvss": cvss,
                    "bucket": bucket,
                    "priority_score": priority_score,
                    "command": command,
                    "download": download or "",
                }
            )

    rows.sort(key=lambda item: (-item["priority_score"], -item["epss"], -item["cvss"]))
    table_rows: list[str] = []
    for item in rows:
        component = item["component"]
        advisory = item["advisory"]
        severity = str(advisory.get("final_risk", "UNKNOWN")).lower()
        download = item["download"]
        download_html = (
            f'<a href="{escape(download)}" target="_blank" rel="noopener noreferrer">Download</a>'
            if download
            else "—"
        )
        table_rows.append(
            f"<tr data-priority='{escape(item['bucket'])}'>"
            f"<td>{escape(item['bucket'])}</td>"
            f"<td>{escape(component.get('name', ''))}</td>"
            f"<td><code>{escape(component.get('version', ''))}</code></td>"
            f"<td>{escape(component.get('ecosystem', ''))}</td>"
            f"<td>{escape(str(advisory.get('cve') or advisory.get('advisory_id') or ''))}</td>"
            f"<td><span class='pill {severity}'>{escape(str(advisory.get('final_risk', 'UNKNOWN')))}</span></td>"
            f"<td>{item['cvss']:.1f}</td>"
            f"<td>{item['epss']:.1%}</td>"
            f"<td>{'Yes' if item['kev'] else 'No'}</td>"
            f"<td><code>{escape(item['command'])}</code></td>"
            f"<td>{download_html}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EPSS Remediation Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#09090b;color:#fafafa;padding:24px}}
.container{{max-width:1320px;margin:0 auto}}
.card{{background:#18181b;border:1px solid #3f3f46;border-radius:12px;padding:18px}}
h1{{margin:0 0 6px}} .meta{{color:#a1a1aa;font-size:0.85rem;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:10px;border-bottom:1px solid #3f3f46;font-size:0.84rem;text-align:left;vertical-align:top}}
th{{text-transform:uppercase;font-size:0.72rem;color:#a1a1aa;letter-spacing:0.05em}}
code{{background:#27272a;padding:2px 6px;border-radius:4px}}
.controls{{display:flex;align-items:center;gap:8px;margin-bottom:12px;color:#a1a1aa;font-size:0.82rem}}
select{{background:#27272a;color:#fafafa;border:1px solid #3f3f46;border-radius:8px;padding:6px 8px}}
.pill{{font-size:0.68rem;font-weight:700;padding:2px 8px;border-radius:999px}}
.pill.critical{{background:rgba(239,68,68,.2);color:#ef4444}}
.pill.high{{background:rgba(249,115,22,.2);color:#f97316}}
.pill.medium{{background:rgba(234,179,8,.2);color:#eab308}}
.pill.low{{background:rgba(34,211,238,.2);color:#22d3ee}}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <h1>EPSS Remediation Queue</h1>
    <div class="meta">{generated_at} · Ranked by KEV, severity, EPSS, and CVSS. Patch in this order.</div>
    <div class="controls">
      <label for="priorityFilter">Filter by Priority</label>
      <select id="priorityFilter">
        <option value="all">All</option>
        <option value="Immediate">Immediate</option>
        <option value="72h">72h</option>
        <option value="7d">7d</option>
        <option value="Backlog">Backlog</option>
      </select>
    </div>
    <table>
      <thead>
        <tr>
          <th>Priority</th><th>Component</th><th>Version</th><th>Ecosystem</th><th>CVE / Advisory</th>
          <th>Severity</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Recommended Fix Command</th><th>Download</th>
        </tr>
      </thead>
      <tbody>{''.join(table_rows) or "<tr><td colspan='11'>No vulnerabilities found.</td></tr>"}</tbody>
    </table>
  </div>
</div>
<script>
(function(){{
  const filter = document.getElementById('priorityFilter');
  const rows = document.querySelectorAll('tbody tr[data-priority]');
  if (!filter) return;
  filter.addEventListener('change', () => {{
    const value = filter.value;
    rows.forEach((row) => {{
      const keep = value === 'all' || row.dataset.priority === value;
      row.style.display = keep ? 'table-row' : 'none';
    }});
  }});
}})();
</script>
</body>
</html>""".strip()

    path.write_text(html, encoding="utf-8")
    return path


def write_combined_html_report(
    project_report: dict[str, Any],
    system_report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Merge project + system scan data and generate a single unified vuln report."""
    p_vulns = project_report.get("vulnerabilities", [])
    s_vulns = system_report.get("vulnerabilities", [])
    p_summary = project_report.get("summary", {})
    s_summary = system_report.get("summary", {})

    merged: dict[str, Any] = {}
    merged["summary"] = {
        k: p_summary.get(k, 0) + s_summary.get(k, 0)
        for k in ("critical", "high", "medium", "low", "unknown")
    }
    merged["components_scanned"] = (
        project_report.get("components_scanned", 0)
        + system_report.get("components_scanned", 0)
    )
    merged["generated_at"] = project_report.get("generated_at") or system_report.get("generated_at", "")

    # Tag vulnerabilities with scan_type
    for g in p_vulns:
        g["_scan_type"] = "project"
    for g in s_vulns:
        g["_scan_type"] = "system"
    merged["vulnerabilities"] = p_vulns + s_vulns

    p_intel = project_report.get("intelligence_sources", {})
    s_intel = system_report.get("intelligence_sources", {})
    p_src = p_intel.get("sources_used", {})
    s_src = s_intel.get("sources_used", {})
    combined_src: dict[str, int] = {}
    for k in set(list(p_src) + list(s_src)):
        combined_src[k] = p_src.get(k, 0) + s_src.get(k, 0)
    merged["intelligence_sources"] = {
        "sources_used": combined_src,
        "multi_source_findings": p_intel.get("multi_source_findings", 0) + s_intel.get("multi_source_findings", 0),
        "total_findings": p_intel.get("total_findings", 0) + s_intel.get("total_findings", 0),
    }

    return _write_combined_html(merged, output_path)


def _write_combined_html(report: dict[str, Any], output_path: str | Path) -> Path:
    """Render combined report HTML with scan-type tabs + severity filters."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    summary = report.get("summary", {})
    vuln_groups = report.get("vulnerabilities", [])
    intel = report.get("intelligence_sources", {})
    generated_at = escape(report.get("generated_at", ""))
    components_scanned = report.get("components_scanned", 0)

    total_vulns = sum(len(g.get("advisories", [])) for g in vuln_groups)
    total_components = len(vuln_groups)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    multi_src = intel.get("multi_source_findings", 0)

    p_groups = [g for g in vuln_groups if g.get("_scan_type") == "project"]
    s_groups = [g for g in vuln_groups if g.get("_scan_type") == "system"]
    p_total = sum(len(g.get("advisories", [])) for g in p_groups)
    s_total = sum(len(g.get("advisories", [])) for g in s_groups)

    # Scatter data
    scatter_data = []
    for group in vuln_groups:
        comp = group.get("component", {})
        for adv in group.get("advisories", []):
            cvss = adv.get("cvss_score") or 0
            epss_val = adv.get("epss") or 0
            if cvss > 0 or epss_val > 0:
                scatter_data.append({
                    "name": comp.get("name", ""), "id": adv.get("advisory_id") or adv.get("cve") or "",
                    "cvss": cvss, "epss": round(epss_val * 100, 2),
                    "sev": (adv.get("final_risk") or "UNKNOWN").lower(), "kev": adv.get("kev", False),
                })
    scatter_data.sort(key=lambda d: -(d["cvss"] * d["epss"]))
    scatter_dots = ""
    for d in scatter_data[:80]:
        left = round(d["epss"] / max(100, 1) * 100, 1)
        bottom = round(d["cvss"] / 10 * 100, 1)
        sev_cls = d["sev"] if d["sev"] in ("critical", "high", "medium", "low") else "unknown"
        size = "10" if d["kev"] else "7"
        tip = escape(f'{d["id"]}: CVSS {d["cvss"]}, EPSS {d["epss"]}%')
        scatter_dots += (
            f'<div class="dot {sev_cls}" style="left:{left}%;bottom:{bottom}%;'
            f'width:{size}px;height:{size}px" title="{tip}"></div>'
        )

    # Build cards
    cards = []
    for group in vuln_groups:
        component = group.get("component", {})
        advisories = group.get("advisories", [])
        sev_summary = group.get("severity_summary", {})
        scan_type = group.get("_scan_type", "unknown")
        comp_name = escape(component.get("name", ""))
        comp_ver = escape(component.get("version", ""))
        comp_eco = escape(component.get("ecosystem", ""))
        remediation_cmd, remediation_link = _component_remediation(component, advisories)
        link_html = ""
        if remediation_link:
            safe_link = escape(remediation_link)
            link_html = f'<a class="download-link" href="{safe_link}" target="_blank" rel="noopener noreferrer">Download update</a>'
        remediation_html = (
            f'<div class="remediation"><div class="rem-title">Recommended fix action</div>'
            f'<code class="rem-cmd">{escape(remediation_cmd)}</code>'
            f'<button class="copy-btn" data-copy="{escape(remediation_cmd)}">Copy command</button>'
            f"{link_html}"
            f"</div>"
        )

        if sev_summary.get("critical"): card_accent = "var(--critical)"
        elif sev_summary.get("high"): card_accent = "var(--high)"
        elif sev_summary.get("medium"): card_accent = "var(--medium)"
        elif sev_summary.get("low"): card_accent = "var(--low)"
        else: card_accent = "var(--border)"

        sev_pills = ""
        for lv, cnt in [("critical", sev_summary.get("critical", 0)),
                         ("high", sev_summary.get("high", 0)),
                         ("medium", sev_summary.get("medium", 0)),
                         ("low", sev_summary.get("low", 0)),
                         ("unknown", sev_summary.get("unknown", 0))]:
            if cnt:
                sev_pills += f'<span class="pill {lv}">{cnt} {lv.upper()}</span>'

        type_tag = f'<span class="scan-tag scan-{scan_type}">{scan_type.upper()}</span>'

        adv_items = []
        for adv in advisories:
            adv_id = escape(adv.get("advisory_id") or "")
            cve = escape(adv.get("cve") or "")
            adv_summary_text = escape(adv.get("summary") or "No description available.")
            if len(adv_summary_text) > 300:
                adv_summary_text = adv_summary_text[:297] + "..."
            sev = (adv.get("final_risk") or "UNKNOWN").lower()
            sev_class = sev if sev in ("critical", "high", "medium", "low") else "unknown"
            cvss = adv.get("cvss_score")
            cvss_html = f'<span class="cvss-badge">{cvss:.1f}</span>' if cvss else ''
            epss = adv.get("epss")
            epss_html = f'<span class="epss-val">{epss:.1%}</span>' if epss else '<span class="epss-val dim">—</span>'
            kev_html = '<span class="kev-badge">⚠ KEV</span>' if adv.get("kev") else ''
            sources = adv.get("sources", [])
            confidence = adv.get("confidence", "low")
            src_html = " ".join(f'<span class="src-tag">{escape(s)}</span>' for s in sources)
            conf_cls = {"high": "conf-high", "medium": "conf-med"}.get(confidence, "conf-low")
            conf_label = f'{len(sources)} source{"s" if len(sources) != 1 else ""}'
            fix_versions = adv.get("fix_versions", [])
            if fix_versions:
                fix_html = '<div class="fix-box">' + "".join(f'<code>{escape(v)}</code>' for v in fix_versions) + '</div>'
            else:
                fix_html = '<div class="fix-box no-fix">No fix available</div>'
            ref_html = ""
            for ref in adv.get("references", []):
                url = ref.get("url", "")
                if url:
                    ref_html = f'<a href="{escape(url)}" target="_blank" rel="noopener noreferrer" class="ref-link">↗ Details</a>'
                    break

            adv_items.append(f"""
            <div class="adv-row" data-sev="{sev_class}">
              <div class="adv-top">
                <div class="adv-id-group">
                  <span class="pill {sev_class}" style="font-size:0.72rem">{sev.upper()}</span>
                  <span class="adv-id">{adv_id}</span>
                  {f'<span class="cve-tag">{cve}</span>' if cve else ''}
                  {cvss_html}
                  {kev_html}
                </div>
                <div class="adv-meta">
                  {epss_html}
                  {src_html}
                  <span class="conf-tag {conf_cls}">{escape(conf_label)}</span>
                  {ref_html}
                </div>
              </div>
              <p class="adv-desc">{adv_summary_text}</p>
              {fix_html}
            </div>""")

        cards.append(f"""
    <div class="comp-card" data-scan="{scan_type}" style="border-left-color:{card_accent}">
      <div class="comp-header">
        <div>
          {type_tag}
          <span class="comp-name">{comp_name}</span>
          <code class="comp-ver">{comp_ver}</code>
          <span class="eco-tag">{comp_eco}</span>
        </div>
        <div class="comp-pills">{sev_pills}</div>
      </div>
      {remediation_html}
      <div class="adv-list">{''.join(adv_items)}</div>
    </div>""")

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Combined Supply Chain &amp; Project Vulnerability Report</title>
<style>
:root {{
  --bg:#09090b; --surface:#18181b; --surface2:#27272a;
  --border:#3f3f46; --text:#fafafa; --muted:#a1a1aa;
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#22d3ee;
  --green:#22c55e; --blue:#3b82f6; --purple:#a78bfa; --radius:12px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text);padding:24px;line-height:1.5}}
.container{{max-width:1060px;margin:0 auto}}
.hdr{{padding:20px 24px;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);margin-bottom:20px;
  display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}
.hdr h1{{font-size:1.4rem;font-weight:700;letter-spacing:-0.02em}}
.hdr-meta{{color:var(--muted);font-size:0.8rem}}
.strip{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px}}
@media(max-width:700px){{.strip{{grid-template-columns:repeat(3,1fr)}}}}
.scard{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:14px;text-align:center}}
.scard .sv{{font-size:1.8rem;font-weight:800;line-height:1}}
.scard .sl{{font-size:0.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;margin-top:4px}}
.scatter-wrap{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;margin-bottom:20px}}
.scatter-wrap h2{{font-size:1rem;font-weight:600;margin-bottom:14px;color:var(--muted)}}
.scatter{{position:relative;width:100%;height:260px;border-left:1px solid var(--border);
  border-bottom:1px solid var(--border)}}
.scatter .axis-x{{position:absolute;bottom:-22px;width:100%;display:flex;
  justify-content:space-between;font-size:0.68rem;color:var(--muted)}}
.scatter .axis-y{{position:absolute;left:-30px;height:100%;display:flex;flex-direction:column-reverse;
  justify-content:space-between;font-size:0.68rem;color:var(--muted)}}
.scatter .axis-label-x{{position:absolute;bottom:-38px;left:50%;transform:translateX(-50%);
  font-size:0.72rem;color:var(--muted)}}
.scatter .axis-label-y{{position:absolute;left:-52px;top:50%;transform:translateY(-50%) rotate(-90deg);
  font-size:0.72rem;color:var(--muted);white-space:nowrap}}
.dot{{position:absolute;border-radius:50%;opacity:0.85;cursor:default;z-index:1}}
.dot.critical{{background:var(--critical)}}
.dot.high{{background:var(--high)}}
.dot.medium{{background:var(--medium)}}
.dot.low{{background:var(--low)}}
.dot.unknown{{background:var(--muted)}}
.scatter .quadrant{{position:absolute;right:0;top:0;width:50%;height:40%;
  background:rgba(239,68,68,0.04);border-radius:0 0 0 8px;
  display:flex;align-items:flex-start;justify-content:flex-end;
  padding:6px 8px;font-size:0.68rem;color:rgba(239,68,68,0.5);pointer-events:none}}
.tab-bar{{display:flex;gap:0;margin-bottom:16px;border-radius:10px;overflow:hidden;border:1px solid var(--border)}}
.tab{{flex:1;padding:10px 0;text-align:center;cursor:pointer;font-weight:600;font-size:0.85rem;
  background:var(--surface);color:var(--muted);transition:all 0.15s;border:none}}
.tab:not(:last-child){{border-right:1px solid var(--border)}}
.tab:hover{{background:var(--surface2);color:var(--text)}}
.tab.active{{background:var(--surface2);color:var(--text);box-shadow:inset 0 -2px 0 var(--green)}}
.tab .tab-count{{font-size:0.72rem;background:var(--surface2);padding:1px 8px;border-radius:99px;margin-left:6px;font-weight:700}}
.tab.active .tab-count{{background:rgba(34,197,94,0.15);color:var(--green)}}
.filter-bar{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}}
.fbtn{{background:var(--surface);border:1px solid var(--border);color:var(--muted);
  padding:6px 16px;border-radius:99px;cursor:pointer;font-size:0.82rem;
  font-weight:600;transition:all 0.15s}}
.fbtn:hover,.fbtn.active{{background:var(--surface2);color:var(--text);border-color:var(--ac,var(--border))}}
.fbtn.active{{box-shadow:0 0 0 1px var(--ac,var(--border))}}
.fbtn-count{{font-size:0.7rem;background:var(--surface2);padding:1px 7px;border-radius:99px;margin-left:4px;font-weight:700}}
.fbtn.active .fbtn-count{{background:rgba(255,255,255,0.1)}}
.adv-row.hidden{{display:none}}
.comp-card.hidden{{display:none}}
.scan-tag{{font-size:0.65rem;font-weight:700;padding:2px 8px;border-radius:4px;
  text-transform:uppercase;letter-spacing:0.04em;margin-right:6px}}
.scan-project{{background:rgba(59,130,246,0.15);color:var(--blue)}}
.scan-system{{background:rgba(167,139,250,0.15);color:var(--purple)}}
.comp-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;margin-bottom:14px;border-left:4px solid var(--border)}}
.comp-header{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px}}
.comp-name{{font-weight:700;font-size:1.05rem}}
.comp-ver{{font-size:0.82rem;background:var(--surface2);padding:2px 8px;border-radius:4px;margin:0 6px}}
.eco-tag{{font-size:0.72rem;color:var(--muted);background:var(--surface2);padding:2px 10px;border-radius:99px}}
.comp-pills{{display:flex;gap:4px;flex-wrap:wrap}}
.pill{{font-size:0.72rem;font-weight:700;padding:3px 10px;border-radius:99px;display:inline-block}}
.pill.critical{{background:rgba(239,68,68,0.15);color:var(--critical)}}
.pill.high{{background:rgba(249,115,22,0.15);color:var(--high)}}
.pill.medium{{background:rgba(234,179,8,0.15);color:var(--medium)}}
.pill.low{{background:rgba(34,211,238,0.15);color:var(--low)}}
.pill.unknown{{background:rgba(161,161,170,0.1);color:var(--muted)}}
.adv-list{{display:flex;flex-direction:column;gap:0}}
.adv-row{{padding:14px 0;border-top:1px solid var(--border)}}
.adv-row:first-child{{border-top:none;padding-top:0}}
.adv-top{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}}
.adv-id-group{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.adv-id{{font-weight:600;font-family:monospace;font-size:0.88rem}}
.cve-tag{{font-size:0.75rem;color:var(--muted);font-family:monospace;
  background:var(--surface2);padding:2px 8px;border-radius:4px}}
.cvss-badge{{font-size:0.72rem;font-weight:700;background:rgba(249,115,22,0.15);
  color:var(--high);padding:2px 8px;border-radius:4px;font-family:monospace}}
.kev-badge{{font-size:0.72rem;font-weight:700;background:rgba(239,68,68,0.2);
  color:var(--critical);padding:2px 8px;border-radius:4px}}
.adv-meta{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.epss-val{{font-size:0.78rem;color:var(--muted);font-family:monospace}}
.epss-val.dim{{opacity:0.4}}
.src-tag{{font-size:0.65rem;padding:2px 7px;border-radius:6px;
  background:rgba(59,130,246,0.12);color:var(--blue);font-weight:700;
  text-transform:uppercase;letter-spacing:0.03em}}
.conf-tag{{font-size:0.65rem;padding:2px 8px;border-radius:6px;font-weight:600}}
.conf-high{{background:rgba(34,197,94,0.15);color:var(--green)}}
.conf-med{{background:rgba(234,179,8,0.12);color:var(--medium)}}
.conf-low{{background:rgba(161,161,170,0.08);color:var(--muted)}}
.ref-link{{font-size:0.78rem;color:var(--blue);text-decoration:none;font-weight:600}}
.ref-link:hover{{text-decoration:underline}}
.adv-desc{{color:var(--muted);font-size:0.84rem;margin:8px 0;line-height:1.5}}
.fix-box{{font-size:0.82rem;margin-top:8px;padding:8px 14px;border-radius:8px;
  background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.15)}}
.fix-box code{{background:rgba(34,197,94,0.15);color:var(--green);padding:2px 8px;
  border-radius:4px;font-size:0.8rem;margin-right:6px}}
.fix-box.no-fix{{color:var(--muted);background:var(--surface2);border-color:var(--border)}}
.remediation{{margin:8px 0 10px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--surface2)}}
.rem-title{{font-size:0.75rem;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em}}
.rem-cmd{{display:block;padding:6px 8px;border-radius:6px;background:#111827;color:#a7f3d0;font-size:0.8rem;white-space:pre-wrap}}
.copy-btn,.download-link{{margin-top:8px;display:inline-block;font-size:0.76rem;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);text-decoration:none;cursor:pointer}}
.download-link{{margin-left:8px}}
.footer{{text-align:center;color:var(--muted);font-size:0.75rem;margin-top:32px;padding:16px}}
</style>
</head>
<body>
<div class="container">

  <div class="hdr">
    <div>
      <h1>🛡 Combined Vulnerability Report</h1>
      <div class="hdr-meta">Project Dependencies + System Supply Chain</div>
      <div class="hdr-meta">{generated_at}</div>
    </div>
    <div style="text-align:right">
      <div class="hdr-meta">{components_scanned} scanned · {total_components} affected · {total_vulns} findings</div>
      <div class="hdr-meta">{multi_src} multi-source confirmed</div>
    </div>
  </div>

  <div class="strip">
    <div class="scard"><div class="sv" style="color:var(--critical)">{critical}</div><div class="sl">Critical</div></div>
    <div class="scard"><div class="sv" style="color:var(--high)">{high}</div><div class="sl">High</div></div>
    <div class="scard"><div class="sv" style="color:var(--medium)">{medium}</div><div class="sl">Medium</div></div>
    <div class="scard"><div class="sv" style="color:var(--low)">{low}</div><div class="sl">Low</div></div>
    <div class="scard"><div class="sv">{total_components}</div><div class="sl">Components</div></div>
    <div class="scard"><div class="sv">{total_vulns}</div><div class="sl">Total</div></div>
  </div>

  <div class="scatter-wrap">
    <h2>CVSS vs EPSS — Risk Heatmap</h2>
    <div class="scatter">
      <div class="quadrant">HIGH RISK ZONE</div>
      {scatter_dots}
      <div class="axis-x"><span>0%</span><span>25%</span><span>50%</span><span>75%</span><span>100%</span></div>
      <div class="axis-y"><span>0</span><span>2.5</span><span>5</span><span>7.5</span><span>10</span></div>
      <div class="axis-label-x">EPSS (Exploit Probability)</div>
      <div class="axis-label-y">CVSS Score</div>
    </div>
  </div>

  <!-- Scan type tabs -->
  <div class="tab-bar">
    <button class="tab active" data-scan="all">All <span class="tab-count">{total_vulns}</span></button>
    <button class="tab" data-scan="project">📦 Project <span class="tab-count">{p_total}</span></button>
    <button class="tab" data-scan="system">🖥 System <span class="tab-count">{s_total}</span></button>
  </div>

  <div class="filter-bar">
    <button class="fbtn active" data-sev="all">All <span class="fbtn-count">{total_vulns}</span></button>
    <button class="fbtn" data-sev="critical" style="--ac:var(--critical)">Critical <span class="fbtn-count">{critical}</span></button>
    <button class="fbtn" data-sev="high" style="--ac:var(--high)">High <span class="fbtn-count">{high}</span></button>
    <button class="fbtn" data-sev="medium" style="--ac:var(--medium)">Medium <span class="fbtn-count">{medium}</span></button>
    <button class="fbtn" data-sev="low" style="--ac:var(--low)">Low <span class="fbtn-count">{low}</span></button>
  </div>

  {''.join(cards) or '<div class="comp-card"><p style="color:var(--muted)">No vulnerabilities found.</p></div>'}

  <div class="footer">Supply Chain Scanner — Combined Report · {escape(generated_at)}</div>
</div>
<script>
(function(){{
  const tabs=document.querySelectorAll('.tab');
  const sevBtns=document.querySelectorAll('.fbtn');
  const cards=document.querySelectorAll('.comp-card');
  const rows=document.querySelectorAll('.adv-row');
  let activeScan='all', activeSev='all';

  function applyFilters(){{
    rows.forEach(r=>{{
      const card=r.closest('.comp-card');
      const scanMatch=activeScan==='all'||card.dataset.scan===activeScan;
      const sevMatch=activeSev==='all'||r.dataset.sev===activeSev;
      r.classList.toggle('hidden',!(scanMatch&&sevMatch));
    }});
    cards.forEach(card=>{{
      const scanMatch=activeScan==='all'||card.dataset.scan===activeScan;
      if(!scanMatch){{card.classList.add('hidden');return}}
      const vis=card.querySelectorAll('.adv-row:not(.hidden)');
      card.classList.toggle('hidden',vis.length===0);
    }});
  }}

  tabs.forEach(t=>{{
    t.addEventListener('click',()=>{{
      tabs.forEach(b=>b.classList.remove('active'));
      t.classList.add('active');
      activeScan=t.dataset.scan;
      applyFilters();
    }});
  }});
  sevBtns.forEach(btn=>{{
    btn.addEventListener('click',()=>{{
      sevBtns.forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      activeSev=btn.dataset.sev;
      applyFilters();
    }});
  }});
}})();
document.querySelectorAll('.copy-btn').forEach((btn)=>{{
  btn.addEventListener('click', async () => {{
    const text = btn.getAttribute('data-copy') || '';
    try {{
      await navigator.clipboard.writeText(text);
      btn.textContent='Copied';
      setTimeout(()=>btn.textContent='Copy command',1200);
    }} catch (_e) {{}}
  }});
}});
</script>
</body>
</html>""".strip()

    path.write_text(html, encoding="utf-8")
    return path
    return path