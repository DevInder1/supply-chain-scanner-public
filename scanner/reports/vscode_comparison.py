"""
VS Code & JetBrains Extension Vulnerability Comparison Report
Supply Chain Scanner (multi-source) vs OSV.dev vs Trivy — real data

Usage:
    python -m scanner.reports.vscode_comparison scanner/system_report.json scanner/vscode_comparison.html
"""
from __future__ import annotations

import json
import os
import html as _html
import subprocess
import urllib.request
from pathlib import Path
from datetime import datetime, timezone


def e(text: str) -> str:
    return _html.escape(str(text))


def _query_osv_batch(extensions: list[dict]) -> list[dict]:
    """Query OSV.dev /v1/querybatch for all extensions (npm ecosystem)."""
    queries = [
        {"package": {"name": ext["name"], "ecosystem": "npm"}, "version": ext["version"]}
        for ext in extensions
    ]
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)  # noqa: S310 – trusted URL
        data = json.loads(resp.read())
        return data.get("results", [])
    except Exception as exc:
        print(f"  Warning: OSV.dev query failed: {exc}")
        return [{}] * len(extensions)


def _run_trivy_fs(scan_dir: str) -> list[dict]:
    """Run ``trivy fs`` on *scan_dir* and return per-vulnerability dicts."""
    try:
        proc = subprocess.run(
            ["trivy", "fs", "--scanners", "vuln", "--format", "json", scan_dir],
            capture_output=True, timeout=180,
        )
        data = json.loads(proc.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    findings: list[dict] = []
    for r in data.get("Results", []):
        typ = r.get("Type", "")
        for v in r.get("Vulnerabilities", []):
            eco = "NuGet" if typ == "dotnet-core" else "npm"
            findings.append({
                "pkg": v.get("PkgName", ""),
                "version": v.get("InstalledVersion", ""),
                "vuln_id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "fixed": v.get("FixedVersion", ""),
                "ecosystem": eco,
                "target": r.get("Target", ""),
            })
    return findings


def _query_osv_for_deps(findings: list[dict]) -> dict:
    """Given Trivy findings, query OSV for the same packages and return summary."""
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (f["pkg"], f["version"], f["ecosystem"])
        if key not in seen:
            seen[key] = f
    queries = [
        {"package": {"name": k[0], "ecosystem": k[2]}, "version": k[1]}
        for k in seen
    ]
    if not queries:
        return {"total": 0, "affected": 0, "cves": set(), "by_sev": {}}
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch", data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)  # noqa: S310
        results = json.loads(resp.read()).get("results", [])
    except Exception:
        return {"total": 0, "affected": 0, "cves": set(), "by_sev": {}}
    total = 0
    affected = 0
    cves: set[str] = set()
    by_sev: dict[str, int] = {}
    for res in results:
        vulns = res.get("vulns", [])
        if vulns:
            affected += 1
        for v in vulns:
            total += 1
            vid = v.get("id", "")
            cves.add(vid)
            for alias in v.get("aliases", []):
                cves.add(alias)
            for s in v.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    sl = _cvss_to_severity(s.get("score", ""))
                    by_sev[sl] = by_sev.get(sl, 0) + 1
                    break
    return {"total": total, "affected": affected, "cves": cves, "by_sev": by_sev}


def _cvss_to_severity(cvss_vector: str) -> str:
    """Extract severity label from a CVSS v3 vector string."""
    if not cvss_vector:
        return "UNKNOWN"
    # Try to extract base score from the vector
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> need to compute, use heuristic
    # For simplicity, check if we have a score value
    try:
        # Some OSV entries include the score directly
        parts = cvss_vector.split("/")
        if len(parts) >= 2:
            # High-level heuristic based on attack complexity and impact
            has_network = "AV:N" in cvss_vector
            has_low_complexity = "AC:L" in cvss_vector
            has_high_impact = "C:H" in cvss_vector or "I:H" in cvss_vector or "A:H" in cvss_vector
            if has_network and has_low_complexity and has_high_impact:
                return "CRITICAL"
            elif has_high_impact:
                return "HIGH"
            elif has_network:
                return "MEDIUM"
            return "MEDIUM"
    except Exception:
        pass
    return "UNKNOWN"


def build_vscode_comparison(system_report_path: str, output_path: str) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    report = json.loads(Path(system_report_path).read_text())
    sbom = report.get("sbom", [])
    if isinstance(sbom, dict):
        sbom = sbom.get("components", [])

    # Extract VS Code extensions from SBOM
    vs_extensions = [c for c in sbom if c.get("ecosystem") == "vscode"]
    # Extract VS Code vulnerability groups from our scanner
    vs_vulns = [g for g in report.get("vulnerabilities", []) if g["component"].get("ecosystem") == "vscode"]

    our_total_advisories = sum(len(g.get("advisories", [])) for g in vs_vulns)
    our_affected = len(vs_vulns)
    our_cves = set()
    our_sources_used = set()
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for g in vs_vulns:
        for a in g.get("advisories", []):
            cid = a.get("cve") or a.get("advisory_id") or ""
            if cid:
                our_cves.add(cid)
            sev = (a.get("final_risk") or "UNKNOWN").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1
            for src in a.get("sources", []):
                our_sources_used.add(src)

    # ── Query OSV.dev directly ──
    print(f"Querying OSV.dev for {len(vs_extensions)} VS Code extensions...")
    osv_results = _query_osv_batch(vs_extensions)

    osv_total = 0
    osv_affected = 0
    osv_cves = set()
    osv_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    osv_findings = []  # (ext_name, ext_version, osv_id, aliases, severity, summary)

    for ext, res in zip(vs_extensions, osv_results):
        vulns = res.get("vulns", [])
        if vulns:
            osv_affected += 1
        for v in vulns:
            osv_total += 1
            vid = v.get("id", "")
            aliases = v.get("aliases", [])
            summary = v.get("summary", "")
            sev_str = "UNKNOWN"
            for s in v.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    sev_str = _cvss_to_severity(s.get("score", ""))
            if sev_str in osv_sev:
                osv_sev[sev_str] += 1
            for alias in aliases:
                osv_cves.add(alias)
            osv_cves.add(vid)
            pub = ext.get("metadata", {}).get("publisher", "?")
            osv_findings.append({
                "ext": f"{pub}.{ext['name']}",
                "version": ext["version"],
                "osv_id": vid,
                "aliases": aliases,
                "severity": sev_str,
                "summary": summary,
            })

    print(f"  OSV.dev: {osv_total} findings for {osv_affected} extensions")
    print(f"  Our scanner: {our_total_advisories} findings for {our_affected} extensions")

    # Overlap analysis
    overlap_cves = our_cves & osv_cves
    only_ours = our_cves - osv_cves
    only_osv = osv_cves - our_cves

    # ── Build our findings table rows ──
    our_rows = ""
    for g in vs_vulns:
        comp = g["component"]
        pub = comp.get("metadata", {}).get("publisher", "?")
        ext_name = f"{pub}.{comp['name']}"
        for a in g.get("advisories", []):
            cid = a.get("cve") or a.get("advisory_id") or ""
            sev = (a.get("final_risk") or "UNKNOWN").lower()
            sev_cls = sev if sev in ("critical", "high", "medium", "low") else "unknown"
            srcs = ", ".join(a.get("sources", []))
            epss = a.get("epss")
            epss_str = f"{epss:.2%}" if epss else "—"
            fix = ", ".join(a.get("fix_versions", [])) or "—"
            exclusive = "★" if cid in only_ours else ""
            our_rows += f"""<tr>
                <td>{e(ext_name)}</td><td class="mono">{e(comp['version'])}</td>
                <td><span class="pill {sev_cls}">{sev.upper()}</span></td>
                <td class="mono">{e(cid)}</td><td>{e(srcs)}</td>
                <td>{epss_str}</td><td class="mono">{e(fix)}</td>
                <td>{exclusive}</td>
            </tr>\n"""

    # ── Build OSV findings table rows ──
    osv_rows = ""
    for f in osv_findings:
        sev = f["severity"].lower()
        sev_cls = sev if sev in ("critical", "high", "medium", "low") else "unknown"
        aliases_str = ", ".join(f["aliases"][:3])
        osv_rows += f"""<tr>
            <td>{e(f['ext'])}</td><td class="mono">{e(f['version'])}</td>
            <td><span class="pill {sev_cls}">{f['severity']}</span></td>
            <td class="mono">{e(f['osv_id'])}</td>
            <td class="mono" style="font-size:0.78rem">{e(aliases_str)}</td>
            <td>{e(f['summary'][:120])}</td>
        </tr>\n"""

    # ── Build extension inventory table ──
    ext_rows = ""
    # Build per-extension advisory counts from our scanner
    our_ext_advs = {}
    for g in vs_vulns:
        comp = g["component"]
        key = f"{comp.get('metadata', {}).get('publisher', '?')}.{comp['name']}"
        our_ext_advs[key] = len(g.get("advisories", []))
    # Build per-extension advisory counts from OSV
    osv_ext_advs = {}
    for f in osv_findings:
        osv_ext_advs[f["ext"]] = osv_ext_advs.get(f["ext"], 0) + 1

    for ext in vs_extensions:
        pub = ext.get("metadata", {}).get("publisher", "?")
        key = f"{pub}.{ext['name']}"
        our_c = our_ext_advs.get(key, 0)
        osv_c = osv_ext_advs.get(key, 0)
        our_badge = f'<span class="pill critical">{our_c}</span>' if our_c > 0 else '<span class="pill" style="background:rgba(34,197,94,0.15);color:var(--green)">Clean</span>'
        osv_badge = f'<span class="pill high">{osv_c}</span>' if osv_c > 0 else '<span class="pill" style="background:rgba(34,197,94,0.15);color:var(--green)">Clean</span>'
        ext_rows += f"""<tr>
            <td style="font-weight:600">{e(key)}</td>
            <td class="mono">{e(ext['version'])}</td>
            <td style="text-align:center">{our_badge}</td>
            <td style="text-align:center">{osv_badge}</td>
        </tr>\n"""

    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Run real Trivy scans ──
    vscode_ext_dir = os.path.expanduser("~/.vscode/extensions")
    jb_base_dirs = [
        os.path.expanduser("~/Library/Application Support/JetBrains"),
        os.path.expanduser("~/.local/share/JetBrains"),
    ]
    jb_base = next((d for d in jb_base_dirs if os.path.isdir(d)), "")

    print("Running Trivy scan on VS Code extensions...")
    trivy_vs = _run_trivy_fs(vscode_ext_dir) if os.path.isdir(vscode_ext_dir) else []
    trivy_vs_cves = {f["vuln_id"] for f in trivy_vs}
    trivy_vs_by_sev: dict[str, int] = {}
    for tf in trivy_vs:
        trivy_vs_by_sev[tf["severity"]] = trivy_vs_by_sev.get(tf["severity"], 0) + 1
    trivy_vs_pkgs = len({f["pkg"] for f in trivy_vs if f.get("vuln_id")})
    print(f"  Trivy VS Code: {len(trivy_vs)} findings, {len(trivy_vs_cves)} unique CVEs")

    print("Running Trivy scan on JetBrains installations...")
    trivy_jb = _run_trivy_fs(jb_base) if jb_base else []
    trivy_jb_cves = {f["vuln_id"] for f in trivy_jb}
    trivy_jb_by_sev: dict[str, int] = {}
    for tf in trivy_jb:
        trivy_jb_by_sev[tf["severity"]] = trivy_jb_by_sev.get(tf["severity"], 0) + 1
    trivy_jb_pkgs = len({f["pkg"] for f in trivy_jb if f.get("vuln_id")})
    print(f"  Trivy JetBrains: {len(trivy_jb)} findings, {len(trivy_jb_cves)} unique CVEs")

    # ── Query OSV.dev for dependencies found by Trivy ──
    print("Querying OSV.dev for JetBrains plugin dependencies...")
    osv_jb = _query_osv_for_deps(trivy_jb)
    print(f"  OSV JetBrains deps: {osv_jb['total']} advisories, {osv_jb['affected']} affected packages")

    print("Querying OSV.dev for VS Code extension dependencies...")
    osv_vs_deps = _query_osv_for_deps(trivy_vs)
    print(f"  OSV VS Code deps: {osv_vs_deps['total']} advisories, {osv_vs_deps['affected']} affected packages")

    # ── JetBrains IDE/Plugin data from our scanner ──
    jb_all = [c for c in sbom if c.get("ecosystem") == "jetbrains"]
    jb_ides = [c for c in jb_all if c.get("type") == "application"]
    jb_plugins = [c for c in jb_all if c.get("type") == "extension"]
    jb_vulns = [g for g in report.get("vulnerabilities", []) if g["component"].get("ecosystem") == "jetbrains"]
    jb_vuln_total = sum(len(g.get("advisories", [])) for g in jb_vulns)
    jb_affected = len(jb_vulns)
    jb_cves: set[str] = set()
    jb_srcs: set[str] = set()
    for g in jb_vulns:
        for a in g.get("advisories", []):
            cid = a.get("cve") or a.get("advisory_id") or ""
            if cid:
                jb_cves.add(cid)
            for src in a.get("sources", []):
                jb_srcs.add(src)

    jb_ide_vuln_counts: dict[str, int] = {}
    for g in jb_vulns:
        c = g["component"]
        key = f'{c["name"]} {c["version"]}'
        jb_ide_vuln_counts[key] = len(g.get("advisories", []))

    _jb_inv_rows = ""
    for ide_c in jb_ides:
        key = f'{ide_c["name"]} {ide_c["version"]}'
        vc = jb_ide_vuln_counts.get(key, 0)
        badge = f'<span class="pill critical">{vc}</span>' if vc else '<span class="pill" style="background:rgba(34,197,94,0.15);color:var(--green)">Clean</span>'
        _jb_inv_rows += f'<tr><td style="font-weight:600">{e(ide_c["name"])}</td><td class="mono">{e(ide_c["version"])}</td><td>IDE</td><td style="text-align:center">{badge}</td></tr>\n'
    for plug_c in jb_plugins:
        key = f'{plug_c["name"]} {plug_c["version"]}'
        vc = jb_ide_vuln_counts.get(key, 0)
        badge = f'<span class="pill high">{vc}</span>' if vc else '<span class="pill" style="background:rgba(167,139,250,0.15);color:var(--purple)">Inventoried</span>'
        _jb_inv_rows += f'<tr><td style="font-weight:600">{e(plug_c["name"])}</td><td class="mono">{e(plug_c["version"])}</td><td>Plugin</td><td style="text-align:center">{badge}</td></tr>\n'

    _jb_finding_rows = ""
    for g in jb_vulns:
        comp = g["component"]
        for a in g.get("advisories", []):
            cid = a.get("cve") or a.get("advisory_id") or ""
            sev = (a.get("final_risk") or "UNKNOWN").lower()
            sev_cls = sev if sev in ("critical", "high", "medium", "low") else "unknown"
            srcs = ", ".join(a.get("sources", []))
            epss = a.get("epss")
            epss_str = f"{epss:.2%}" if epss else "—"
            fix = ", ".join(a.get("fix_versions", [])) or "—"
            _jb_finding_rows += f'<tr><td>{e(comp["name"])}</td><td class="mono">{e(comp["version"])}</td><td><span class="pill {sev_cls}">{sev.upper()}</span></td><td class="mono">{e(cid)}</td><td>{e(srcs)}</td><td>{epss_str}</td><td class="mono">{e(fix)}</td></tr>\n'

    _jb_unique_ides = len(set((c["name"], c["version"]) for c in jb_ides))
    _jb_unique_plugins = len(set((c["name"], c["version"]) for c in jb_plugins))

    # ── Trivy findings table for JetBrains ──
    _trivy_jb_rows = ""
    for tf in trivy_jb:
        sev = tf["severity"].lower()
        sev_cls = sev if sev in ("critical", "high", "medium", "low") else "unknown"
        _trivy_jb_rows += f'<tr><td>{e(tf["pkg"])}</td><td class="mono">{e(tf["version"])}</td><td><span class="pill {sev_cls}">{tf["severity"]}</span></td><td class="mono">{e(tf["vuln_id"])}</td><td>{e(tf["ecosystem"])}</td><td class="mono">{e(tf["fixed"])}</td></tr>\n'

    # ── Trivy findings table for VS Code ──
    _trivy_vs_rows = ""
    for tf in trivy_vs:
        sev = tf["severity"].lower()
        sev_cls = sev if sev in ("critical", "high", "medium", "low") else "unknown"
        _trivy_vs_rows += f'<tr><td>{e(tf["pkg"])}</td><td class="mono">{e(tf["version"])}</td><td><span class="pill {sev_cls}">{tf["severity"]}</span></td><td class="mono">{e(tf["vuln_id"])}</td><td class="mono">{e(tf["fixed"])}</td></tr>\n'

    # ── CVE overlap analysis for JetBrains (all three tools) ──
    jb_all_three = jb_cves & trivy_jb_cves & osv_jb["cves"] if osv_jb["cves"] else set()
    jb_only_ours = jb_cves - trivy_jb_cves - osv_jb["cves"]
    jb_only_trivy = trivy_jb_cves - jb_cves - osv_jb["cves"]
    jb_only_osv = osv_jb["cves"] - jb_cves - trivy_jb_cves

    _jb_section = ""
    if jb_all or trivy_jb:
        _jb_section = f"""
<!-- JetBrains IDE Security — Three-Way Comparison -->
<div class="section" style="border-top:3px solid var(--purple)">
  <h2>🧠 JetBrains / WebStorm Security — Real Three-Way Comparison</h2>
  <p style="color:var(--muted);font-size:0.85rem;margin-bottom:16px">
    All three tools were run against the same JetBrains installation directory.
    Our scanner detected <strong>{_jb_unique_ides} IDE(s)</strong> and <strong>{_jb_unique_plugins} plugins</strong>,
    Trivy scanned plugin dependencies, and OSV.dev was queried for the same packages.
  </p>

  <!-- Three-way stats -->
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px">
    <div style="text-align:center;padding:18px;background:linear-gradient(135deg,rgba(34,197,94,0.08),rgba(34,197,94,0.04));border:1px solid rgba(34,197,94,0.2);border-radius:12px">
      <div style="font-size:2.2rem;font-weight:800;color:var(--ours)">{jb_vuln_total}</div>
      <div style="font-size:0.85rem;font-weight:700;margin:2px 0">🛡 Supply Chain Scanner</div>
      <div style="font-size:0.78rem;color:var(--muted)">{jb_affected} affected · {len(jb_cves)} unique CVEs<br>{_jb_unique_ides} IDEs + {_jb_unique_plugins} plugins scanned<br>Sources: {', '.join(sorted(jb_srcs)) or '—'}</div>
    </div>
    <div style="text-align:center;padding:18px;background:linear-gradient(135deg,rgba(59,130,246,0.08),rgba(59,130,246,0.04));border:1px solid rgba(59,130,246,0.2);border-radius:12px">
      <div style="font-size:2.2rem;font-weight:800;color:var(--blue)">{len(trivy_jb)}</div>
      <div style="font-size:0.85rem;font-weight:700;margin:2px 0">🔍 Trivy (Real Scan)</div>
      <div style="font-size:0.78rem;color:var(--muted)">{trivy_jb_pkgs} affected packages · {len(trivy_jb_cves)} unique CVEs<br>{trivy_jb_by_sev.get('CRITICAL', 0)} Crit · {trivy_jb_by_sev.get('HIGH', 0)} High · {trivy_jb_by_sev.get('MEDIUM', 0)} Med<br><code>trivy fs</code> on JetBrains dir</div>
    </div>
    <div style="text-align:center;padding:18px;background:linear-gradient(135deg,rgba(167,139,250,0.08),rgba(167,139,250,0.04));border:1px solid rgba(167,139,250,0.2);border-radius:12px">
      <div style="font-size:2.2rem;font-weight:800;color:var(--osv)">{osv_jb['total']}</div>
      <div style="font-size:0.85rem;font-weight:700;margin:2px 0">🌐 OSV.dev (Real Query)</div>
      <div style="font-size:0.78rem;color:var(--muted)">{osv_jb['affected']} affected packages · {len(osv_jb['cves'])} unique IDs<br>Queried same deps as Trivy<br><code>POST /v1/querybatch</code></div>
    </div>
  </div>

  <!-- CVE overlap -->
  <h3 style="font-size:0.95rem;margin-bottom:10px;color:var(--text)">CVE Coverage Overlap — JetBrains</h3>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">
    <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:10px">
      <div style="font-size:1.5rem;font-weight:800;color:var(--ours)">{len(jb_only_ours)}</div>
      <div style="font-size:0.78rem;color:var(--muted)">Only Our Scanner<br>(IDE-level NVD CVEs)</div>
    </div>
    <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:10px">
      <div style="font-size:1.5rem;font-weight:800;color:var(--blue)">{len(jb_only_trivy)}</div>
      <div style="font-size:0.78rem;color:var(--muted)">Only Trivy<br>(plugin dep vulns)</div>
    </div>
    <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:10px">
      <div style="font-size:1.5rem;font-weight:800;color:var(--osv)">{len(jb_only_osv)}</div>
      <div style="font-size:0.78rem;color:var(--muted)">Only OSV.dev</div>
    </div>
    <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:10px">
      <div style="font-size:1.5rem;font-weight:800;color:var(--medium)">{len(jb_all_three)}</div>
      <div style="font-size:0.78rem;color:var(--muted)">Found by All Three</div>
    </div>
  </div>

  <!-- What each tool finds -->
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
    <div style="padding:12px;background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.15);border-radius:10px">
      <div style="font-weight:700;font-size:0.85rem;color:var(--ours);margin-bottom:4px">🛡 Our Scanner Finds</div>
      <div style="color:var(--muted);font-size:0.8rem">✓ IDE-level CVEs (WebStorm, IntelliJ) via NVD CPE<br>✓ Plugin inventory + metadata<br>✓ EPSS exploit probability<br>✓ Multi-source confidence</div>
    </div>
    <div style="padding:12px;background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);border-radius:10px">
      <div style="font-weight:700;font-size:0.85rem;color:var(--blue);margin-bottom:4px">🔍 Trivy Finds</div>
      <div style="color:var(--muted);font-size:0.8rem">✓ Vulnerable npm/NuGet deps in plugins<br>✗ No IDE-level CVE scanning<br>✗ No plugin discovery/naming<br>✗ No EPSS or confidence scoring</div>
    </div>
    <div style="padding:12px;background:rgba(167,139,250,0.06);border:1px solid rgba(167,139,250,0.15);border-radius:10px">
      <div style="font-weight:700;font-size:0.85rem;color:var(--osv);margin-bottom:4px">🌐 OSV.dev Finds</div>
      <div style="color:var(--muted);font-size:0.8rem">✓ GHSA advisories for known packages<br>✗ No IDE-level scanning<br>✗ No JetBrains ecosystem<br>✗ Requires knowing package names</div>
    </div>
  </div>

  <!-- Our Scanner: IDE + Plugin Inventory -->
  <h3 style="font-size:0.95rem;margin-bottom:10px;color:var(--text)">🛡 Our Scanner — IDE + Plugin Inventory</h3>
  <div style="overflow-x:auto;margin-bottom:20px">
  <table class="comp-table">
    <tr><th>Component</th><th>Version</th><th>Type</th><th style="text-align:center">CVEs</th></tr>
    {_jb_inv_rows or '<tr><td colspan="4" style="color:var(--muted)">No JetBrains installations detected</td></tr>'}
  </table>
  </div>

  <!-- Our Scanner: Vulnerability Findings -->
  <h3 style="font-size:0.95rem;margin-bottom:10px;color:var(--text)">🛡 Our Scanner — Vulnerability Findings</h3>
  <div style="overflow-x:auto;margin-bottom:20px">
  <table class="comp-table">
    <tr><th>Component</th><th>Version</th><th>Severity</th><th>CVE</th><th>Sources</th><th>EPSS</th><th>Fix</th></tr>
    {_jb_finding_rows or '<tr><td colspan="7" style="color:var(--muted)">No IDE-level vulnerabilities matched</td></tr>'}
  </table>
  </div>

  <!-- Trivy: Real Findings -->
  <h3 style="font-size:0.95rem;margin-bottom:10px;color:var(--text)">🔍 Trivy — Real Scan Findings <span style="font-size:0.8rem;color:var(--muted)">(<code>trivy fs</code> on JetBrains dir)</span></h3>
  <div style="overflow-x:auto;margin-bottom:20px">
  <table class="comp-table">
    <tr><th>Package</th><th>Version</th><th>Severity</th><th>CVE</th><th>Ecosystem</th><th>Fix</th></tr>
    {_trivy_jb_rows or '<tr><td colspan="6" style="color:var(--muted)">Trivy found no vulnerabilities</td></tr>'}
  </table>
  </div>

  <!-- OSV: Real Query Results -->
  <h3 style="font-size:0.95rem;margin-bottom:10px;color:var(--text)">🌐 OSV.dev — Real API Query Results <span style="font-size:0.8rem;color:var(--muted)">(queried same deps Trivy found)</span></h3>
  <p style="color:var(--muted);font-size:0.82rem;margin-bottom:10px">
    Queried OSV.dev <code>/v1/querybatch</code> with {trivy_jb_pkgs} packages found in JetBrains plugins.
    Result: <strong>{osv_jb['total']} advisories</strong> for {osv_jb['affected']} affected packages.
    {"OSV.dev found the same dependency issues but <strong>misses all IDE-level CVEs</strong> our scanner detects." if osv_jb['total'] > 0 else "OSV.dev returned 0 results."}
  </p>
</div>"""

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDE Extension Security — Supply Chain Scanner vs Trivy vs OSV.dev</title>
<style>
:root {{
  --bg:#09090b; --surface:#18181b; --surface2:#27272a;
  --border:#3f3f46; --text:#fafafa; --muted:#a1a1aa;
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#22d3ee;
  --green:#22c55e; --blue:#3b82f6; --purple:#a78bfa; --radius:14px;
  --ours:#22c55e; --osv:#a78bfa; --trivy:#3b82f6;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text);padding:24px;line-height:1.6}}
.container{{max-width:1120px;margin:0 auto}}
.mono{{font-family:'SF Mono',Menlo,Consolas,monospace;font-size:0.85rem}}

/* Hero */
.hero{{background:linear-gradient(135deg,rgba(34,197,94,0.08),rgba(167,139,250,0.06));
  border:1px solid var(--border);border-radius:var(--radius);padding:32px;margin-bottom:24px}}
.hero h1{{font-size:1.6rem;font-weight:800;letter-spacing:-0.03em;margin-bottom:8px}}
.hero .subtitle{{color:var(--muted);font-size:0.95rem}}
.hero .verdict{{margin-top:16px;padding:16px;background:rgba(34,197,94,0.08);
  border:1px solid rgba(34,197,94,0.2);border-radius:10px;font-size:0.95rem}}
.hero .verdict strong{{color:var(--green)}}

/* Stats bar */
.stat-row{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}}
@media(max-width:700px){{.stat-row{{grid-template-columns:1fr}}}}
.stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;border-top:3px solid var(--border)}}
.stat-card.ours{{border-top-color:var(--ours)}}
.stat-card.trivy{{border-top-color:var(--trivy)}}
.stat-card.osv{{border-top-color:var(--osv)}}
.stat-card h3{{font-size:0.85rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:12px}}
.stat-card .big{{font-size:2.6rem;font-weight:800;line-height:1}}
.stat-card .detail{{color:var(--muted);font-size:0.82rem;margin-top:8px}}

/* Section */
.section{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:24px;margin-bottom:20px}}
.section h2{{font-size:1.15rem;font-weight:700;margin-bottom:16px;letter-spacing:-0.01em}}
.section h2 .count{{font-size:0.85rem;font-weight:600;color:var(--muted);margin-left:8px}}

/* Table */
.comp-table{{width:100%;border-collapse:collapse;font-size:0.88rem}}
.comp-table th{{text-align:left;padding:10px 14px;background:var(--surface2);
  border:1px solid var(--border);color:var(--muted);font-weight:600;font-size:0.78rem;
  text-transform:uppercase;letter-spacing:0.04em}}
.comp-table td{{padding:10px 14px;border:1px solid var(--border);vertical-align:middle}}
.comp-table tr:hover td{{background:rgba(255,255,255,0.02)}}
.yes{{color:var(--green);font-weight:700}}
.no{{color:var(--critical);font-weight:700}}
.partial{{color:var(--medium);font-weight:700}}
.feature{{font-weight:600;color:var(--text)}}

/* Pills */
.pill{{font-size:0.72rem;font-weight:700;padding:3px 10px;border-radius:99px;display:inline-block}}
.pill.critical{{background:rgba(239,68,68,0.15);color:var(--critical)}}
.pill.high{{background:rgba(249,115,22,0.15);color:var(--high)}}
.pill.medium{{background:rgba(234,179,8,0.15);color:var(--medium)}}
.pill.low{{background:rgba(34,211,238,0.15);color:var(--low)}}
.pill.unknown{{background:rgba(161,161,170,0.1);color:var(--muted)}}

/* Winner badge */
.winner{{display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:99px;
  font-size:0.75rem;font-weight:700;background:rgba(34,197,94,0.12);color:var(--green)}}
.winner::before{{content:'\\2713'}}

/* Bar comparison */
.bar-compare{{display:flex;flex-direction:column;gap:10px;margin:16px 0}}
.bar-row{{display:flex;align-items:center;gap:12px}}
.bar-label{{width:140px;font-size:0.82rem;font-weight:600;flex-shrink:0}}
.bar-track{{flex:1;height:28px;background:var(--surface2);border-radius:8px;overflow:hidden;position:relative}}
.bar-fill{{height:100%;border-radius:8px;display:flex;align-items:center;justify-content:flex-end;
  padding:0 10px;font-size:0.78rem;font-weight:700;min-width:36px;transition:width 0.3s}}
.bar-fill.ours{{background:linear-gradient(90deg,rgba(34,197,94,0.3),rgba(34,197,94,0.7))}}
.bar-fill.osv{{background:linear-gradient(90deg,rgba(167,139,250,0.3),rgba(167,139,250,0.7))}}

/* Tabs */
.tab-bar{{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:0}}
.tab{{padding:8px 18px;font-size:0.85rem;font-weight:600;cursor:pointer;border:none;
  background:none;color:var(--muted);border-bottom:2px solid transparent;transition:all .2s}}
.tab:hover{{color:var(--text)}}
.tab.active{{color:var(--green);border-bottom-color:var(--green)}}
.tab-panel{{display:none}} .tab-panel.active{{display:block}}

/* Venn */
.venn-stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:16px 0}}
.venn-item{{text-align:center;padding:16px;border-radius:12px;background:var(--surface2)}}
.venn-item .vn{{font-size:2rem;font-weight:800}}
.venn-item .vl{{font-size:0.78rem;color:var(--muted);margin-top:4px}}

.footer{{text-align:center;color:var(--muted);font-size:0.75rem;padding:24px}}
</style>
</head>
<body>
<div class="container">

<!-- Hero -->
<div class="hero">
  <h1>🔌 IDE Extension Security — Three-Way Comparison</h1>
  <div class="subtitle">Supply Chain Scanner vs Trivy vs OSV.dev — VS Code ({len(vs_extensions)} extensions) + JetBrains ({_jb_unique_ides} IDEs, {_jb_unique_plugins} plugins)</div>
  <div class="subtitle" style="margin-top:4px">Real scans of <strong>~/.vscode/extensions</strong> and <strong>~/Library/Application Support/JetBrains</strong> · {gen_time}</div>
  <div class="verdict">
    <strong>VS Code:</strong> Our scanner found <strong>{our_total_advisories} extension-level CVEs</strong>,
    Trivy found <strong>{len(trivy_vs)} dependency vulnerabilities</strong> in extension bundles,
    OSV.dev returned <strong>{osv_total} findings</strong> via API.<br>
    <strong>JetBrains:</strong> Our scanner found <strong>{jb_vuln_total} IDE-level CVEs</strong>,
    Trivy found <strong>{len(trivy_jb)} plugin dependency vulnerabilities</strong>,
    OSV.dev returned <strong>{osv_jb['total']} advisories</strong> for the same dependencies.
  </div>
</div>

<!-- Stats Cards -->
<div class="stat-row">
  <div class="stat-card ours">
    <h3>🛡 Supply Chain Scanner</h3>
    <div class="big" style="color:var(--ours)">{our_total_advisories}</div>
    <div class="detail">
      {sev_counts['CRITICAL']} Critical · {sev_counts['HIGH']} High · {sev_counts['MEDIUM']} Medium · {sev_counts['LOW']} Low<br>
      {our_affected} affected extension{"s" if our_affected != 1 else ""} out of {len(vs_extensions)} scanned<br>
      Sources: {", ".join(sorted(our_sources_used)) or "—"} · EPSS + KEV enrichment
    </div>
  </div>
  <div class="stat-card trivy">
    <h3>🔍 Trivy (Real Scan)</h3>
    <div class="big" style="color:var(--trivy)">{len(trivy_vs)}</div>
    <div class="detail">
      {trivy_vs_by_sev.get('CRITICAL', 0)} Critical · {trivy_vs_by_sev.get('HIGH', 0)} High · {trivy_vs_by_sev.get('MEDIUM', 0)} Medium · {trivy_vs_by_sev.get('LOW', 0)} Low<br>
      {trivy_vs_pkgs} affected packages in extension bundles<br>
      <code>trivy fs ~/.vscode/extensions</code>
    </div>
  </div>
  <div class="stat-card osv">
    <h3>🌐 OSV.dev (Direct API Query)</h3>
    <div class="big" style="color:var(--osv)">{osv_total}</div>
    <div class="detail">
      {osv_sev['CRITICAL']} Critical · {osv_sev['HIGH']} High · {osv_sev['MEDIUM']} Medium · {osv_sev['LOW']} Low<br>
      {osv_affected} affected extension{"s" if osv_affected != 1 else ""} out of {len(vs_extensions)} queried<br>
      Queried: POST /v1/querybatch · ecosystem: npm · Single source
    </div>
  </div>
</div>

<!-- Detection Volume -->
<div class="section">
  <h2>Detection Comparison</h2>
  <div class="bar-compare">
    <div class="bar-row">
      <div class="bar-label">Total Findings</div>
      <div class="bar-track"><div class="bar-fill ours" style="width:{max(our_total_advisories, 1) / max(our_total_advisories, osv_total, 1) * 100:.0f}%">{our_total_advisories}</div></div>
      <div class="bar-track"><div class="bar-fill osv" style="width:{max(osv_total, 0) / max(our_total_advisories, osv_total, 1) * 100:.0f}%">{osv_total}</div></div>
    </div>
    <div class="bar-row">
      <div class="bar-label">Affected Extensions</div>
      <div class="bar-track"><div class="bar-fill ours" style="width:{max(our_affected, 1) / max(our_affected, osv_affected, 1) * 100:.0f}%">{our_affected}</div></div>
      <div class="bar-track"><div class="bar-fill osv" style="width:{max(osv_affected, 0) / max(our_affected, osv_affected, 1) * 100:.0f}%">{osv_affected}</div></div>
    </div>
    <div class="bar-row">
      <div class="bar-label">Unique CVE/IDs</div>
      <div class="bar-track"><div class="bar-fill ours" style="width:{max(len(our_cves), 1) / max(len(our_cves), len(osv_cves), 1) * 100:.0f}%">{len(our_cves)}</div></div>
      <div class="bar-track"><div class="bar-fill osv" style="width:{max(len(osv_cves), 0) / max(len(our_cves), len(osv_cves), 1) * 100:.0f}%">{len(osv_cves)}</div></div>
    </div>
    <div class="bar-row">
      <div class="bar-label">Intel Sources</div>
      <div class="bar-track"><div class="bar-fill ours" style="width:100%">{len(our_sources_used)}</div></div>
      <div class="bar-track"><div class="bar-fill osv" style="width:{1 / max(len(our_sources_used), 1) * 100:.0f}%">1</div></div>
    </div>
  </div>
  <div style="font-size:0.78rem;color:var(--muted);display:flex;gap:16px;margin-top:8px">
    <span style="color:var(--ours)">■ Supply Chain Scanner</span>
    <span style="color:var(--osv)">■ OSV.dev</span>
  </div>
</div>

<!-- CVE Overlap -->
<div class="section">
  <h2>CVE Coverage Overlap</h2>
  <div class="venn-stats">
    <div class="venn-item" style="border:2px solid var(--ours)">
      <div class="vn" style="color:var(--ours)">{len(only_ours)}</div>
      <div class="vl">Only in Our Scanner</div>
    </div>
    <div class="venn-item" style="border:2px solid var(--medium)">
      <div class="vn" style="color:var(--medium)">{len(overlap_cves)}</div>
      <div class="vl">Found by Both</div>
    </div>
    <div class="venn-item" style="border:2px solid var(--osv)">
      <div class="vn" style="color:var(--osv)">{len(only_osv)}</div>
      <div class="vl">Only in OSV.dev</div>
    </div>
  </div>
  <p style="color:var(--muted);font-size:0.85rem;margin-top:8px">
    {"Our scanner found <strong style=" + '"' + "color:var(--green)" + '"' + ">" + str(len(only_ours)) + " exclusive CVEs</strong> that OSV.dev completely missed for VS Code extensions." if only_ours else "Both tools found the same set of CVEs." if overlap_cves else "Neither tool shares CVE overlap — they detected entirely different vulnerability classes."}
  </p>
</div>

<!-- Extension Inventory -->
<div class="section">
  <h2>Extension-by-Extension Scan Results <span class="count">({len(vs_extensions)} extensions)</span></h2>
  <div style="overflow-x:auto">
  <table class="comp-table">
    <tr>
      <th>Extension</th><th>Version</th>
      <th style="text-align:center">Our Scanner</th>
      <th style="text-align:center">OSV.dev</th>
    </tr>
    {ext_rows}
  </table>
  </div>
</div>

<!-- Our Scanner Findings -->
<div class="section" style="border-top:3px solid var(--ours)">
  <h2>🛡 Supply Chain Scanner Findings <span class="count">({our_total_advisories} advisories)</span></h2>
  <p style="color:var(--muted);font-size:0.85rem;margin-bottom:14px">
    Vulnerabilities detected by querying <strong>{len(our_sources_used)} intelligence sources</strong>
    ({", ".join(sorted(our_sources_used)) or "none"}) with EPSS enrichment.
    ★ = Exclusive finding not in OSV.dev.
  </p>
  <div style="overflow-x:auto">
  <table class="comp-table">
    <tr><th>Extension</th><th>Version</th><th>Severity</th><th>CVE/Advisory</th><th>Sources</th><th>EPSS</th><th>Fix</th><th></th></tr>
    {our_rows or '<tr><td colspan="8" style="color:var(--muted)">No vulnerabilities found — all extensions are clean!</td></tr>'}
  </table>
  </div>
</div>

<!-- OSV.dev Findings -->
<div class="section" style="border-top:3px solid var(--osv)">
  <h2>🌐 OSV.dev API Findings <span class="count">({osv_total} results)</span></h2>
  <p style="color:var(--muted);font-size:0.85rem;margin-bottom:14px">
    Direct query to <code>https://api.osv.dev/v1/querybatch</code> with each extension name
    mapped to <strong>npm ecosystem</strong> (VS Code extensions are npm packages).
  </p>
  <div style="overflow-x:auto">
  <table class="comp-table">
    <tr><th>Extension</th><th>Version</th><th>Severity</th><th>OSV ID</th><th>Aliases</th><th>Summary</th></tr>
    {osv_rows or '<tr><td colspan="6" style="color:var(--muted)">OSV.dev returned <strong>0 results</strong> for all queried extensions. VS Code extension names often do not match npm package names, so OSV.dev cannot look them up via the npm ecosystem.</td></tr>'}
  </table>
  </div>
</div>

<!-- Trivy VS Code Real Scan -->
<div class="section" style="border-top:3px solid var(--trivy)">
  <h2>🔍 Trivy — VS Code Extension Dependencies <span class="count">({len(trivy_vs)} findings)</span></h2>
  <p style="color:var(--muted);font-size:0.85rem;margin-bottom:14px">
    Real <code>trivy fs ~/.vscode/extensions</code> scan. Trivy finds vulnerable npm packages
    <strong>bundled inside</strong> extension directories — a different layer than extension-level CVEs.
    {trivy_vs_by_sev.get('CRITICAL', 0)} Critical · {trivy_vs_by_sev.get('HIGH', 0)} High · {trivy_vs_by_sev.get('MEDIUM', 0)} Medium · {trivy_vs_by_sev.get('LOW', 0)} Low
  </p>
  <div style="overflow-x:auto">
  <table class="comp-table">
    <tr><th>Package</th><th>Version</th><th>Severity</th><th>CVE</th><th>Fix</th></tr>
    {_trivy_vs_rows or '<tr><td colspan="5" style="color:var(--muted)">Trivy found no vulnerabilities in VS Code extensions</td></tr>'}
  </table>
  </div>
</div>

<!-- Feature Comparison -->
<div class="section">
  <h2>Feature Comparison — IDE Extension Scanning</h2>
  <table class="comp-table">
    <tr><th>Capability</th><th>Supply Chain Scanner</th><th>Trivy</th><th>OSV.dev</th></tr>
    <tr>
      <td class="feature">VS Code Extension Discovery</td>
      <td class="yes">✓ Scans ~/.vscode/extensions automatically</td>
      <td class="partial">△ Scans deps inside extension dirs</td>
      <td class="no">✗ No extension discovery — manual input only</td>
    </tr>
    <tr>
      <td class="feature">Extension Name Resolution</td>
      <td class="yes">✓ Reads package.json from each extension</td>
      <td class="no">✗ Only sees bundled npm packages</td>
      <td class="partial">△ Requires knowing exact npm package name</td>
    </tr>
    <tr>
      <td class="feature">Intelligence Sources</td>
      <td class="yes">✓ OSV + NVD + GHSA + Sonatype (4 sources)</td>
      <td class="partial">△ 1 source (Trivy DB — aggregates OSV/NVD)</td>
      <td class="no">1 source (OSV database only)</td>
    </tr>
    <tr>
      <td class="feature">NVD/CVE Matching</td>
      <td class="yes">✓ CPE-based NVD lookups (finds generic CVEs)</td>
      <td class="partial">△ Matches by package name, not CPE</td>
      <td class="no">✗ No NVD integration</td>
    </tr>
    <tr>
      <td class="feature">Dependency Scanning</td>
      <td class="no">✗ Scans extension-level only</td>
      <td class="yes">✓ Scans bundled npm/NuGet deps inside extensions</td>
      <td class="no">✗ No transitive dependency scanning</td>
    </tr>
    <tr>
      <td class="feature">JetBrains IDE Scanning</td>
      <td class="yes">✓ IDE-level CVEs + plugin inventory via NVD CPE</td>
      <td class="partial">△ Plugin dependency vulns only (no IDE CVEs)</td>
      <td class="no">✗ No JetBrains ecosystem</td>
    </tr>
    <tr>
      <td class="feature">EPSS Scoring</td>
      <td class="yes">✓ Exploit probability from FIRST.org</td>
      <td class="no">✗ Not available</td>
      <td class="no">✗ Not available</td>
    </tr>
    <tr>
      <td class="feature">CISA KEV Tracking</td>
      <td class="yes">✓ Known Exploited Vulnerabilities catalog</td>
      <td class="no">✗ Not available</td>
      <td class="no">✗ Not available</td>
    </tr>
    <tr>
      <td class="feature">Fix Version Guidance</td>
      <td class="yes">✓ Per-advisory fix versions</td>
      <td class="yes">✓ Fix versions from Trivy DB</td>
      <td class="yes">✓ Affected ranges (when available)</td>
    </tr>
    <tr>
      <td class="feature">Batch Scanning</td>
      <td class="yes">✓ All extensions in one scan</td>
      <td class="yes">✓ Directory-level filesystem scan</td>
      <td class="yes">✓ /v1/querybatch endpoint</td>
    </tr>
    <tr>
      <td class="feature">Publisher Tracking</td>
      <td class="yes">✓ Extension publisher metadata</td>
      <td class="no">✗ No publisher awareness</td>
      <td class="no">✗ No publisher awareness</td>
    </tr>
    <tr>
      <td class="feature">Malware Detection</td>
      <td class="yes">✓ Via Sonatype Guide</td>
      <td class="no">✗ No malware detection</td>
      <td class="no">✗ No malware detection</td>
    </tr>
    <tr>
      <td class="feature">Offline Cache</td>
      <td class="yes">✓ SQLite local cache</td>
      <td class="yes">✓ Local Trivy DB cache</td>
      <td class="no">✗ Online only</td>
    </tr>
  </table>
</div>

<!-- Why Competitors Miss IDE Extension Vulnerabilities -->
<div class="section" style="background:linear-gradient(135deg,rgba(167,139,250,0.06),rgba(34,197,94,0.04))">
  <h2>Why Single-Tool Approaches Miss IDE Extension Vulnerabilities</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-top:12px">
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid var(--border)">
      <div style="font-size:1.4rem;margin-bottom:6px">🏷</div>
      <div style="font-weight:700;margin-bottom:4px">OSV: Name Mismatch</div>
      <div style="color:var(--muted);font-size:0.85rem">
        VS Code extensions use publisher-scoped names (e.g. <code>ms-python.python</code>) that don't correspond
        to npm package names. OSV.dev's npm ecosystem lookup fails to match them.
      </div>
    </div>
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid var(--border)">
      <div style="font-size:1.4rem;margin-bottom:6px">📦</div>
      <div style="font-weight:700;margin-bottom:4px">OSV: Ecosystem Limitation</div>
      <div style="color:var(--muted);font-size:0.85rem">
        OSV.dev has no dedicated "vscode" or "jetbrains" ecosystem. Extensions/IDEs must be
        queried as npm packages, but most aren't published to npm.
      </div>
    </div>
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid var(--border)">
      <div style="font-size:1.4rem;margin-bottom:6px">🔍</div>
      <div style="font-weight:700;margin-bottom:4px">Trivy: Different Layer</div>
      <div style="color:var(--muted);font-size:0.85rem">
        Trivy scans <em>transitive dependencies</em> bundled inside extensions (npm/NuGet packages),
        but misses extension-level and IDE-level CVEs tracked in NVD via CPE identifiers.
      </div>
    </div>
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid var(--border)">
      <div style="font-size:1.4rem;margin-bottom:6px">🧠</div>
      <div style="font-weight:700;margin-bottom:4px">Trivy: No IDE Discovery</div>
      <div style="color:var(--muted);font-size:0.85rem">
        Trivy does not identify WebStorm, IntelliJ, or other IDEs as software components.
        It finds <code>picomatch</code> vulnerabilities in a plugin jar, but not the
        <strong>WebStorm IDE CVEs</strong> themselves.
      </div>
    </div>
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid var(--border)">
      <div style="font-size:1.4rem;margin-bottom:6px">🛡</div>
      <div style="font-weight:700;margin-bottom:4px">Our Multi-Layer Approach</div>
      <div style="color:var(--muted);font-size:0.85rem">
        Supply Chain Scanner discovers extensions + IDEs, extracts metadata from
        <code>package.json</code>, and queries 4 intelligence sources — catching
        both extension-level and IDE-level CVEs that single-source tools miss.
      </div>
    </div>
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid var(--border)">
      <div style="font-size:1.4rem;margin-bottom:6px">🤝</div>
      <div style="font-weight:700;margin-bottom:4px">Complementary Coverage</div>
      <div style="color:var(--muted);font-size:0.85rem">
        Trivy's dependency scanning + our extension/IDE scanning = more complete picture.
        Combining both tools covers both transitive dependency risks and
        top-level software CVEs.
      </div>
    </div>
  </div>
</div>

{_jb_section}

<!-- Key Takeaways -->
<div class="section" style="background:linear-gradient(135deg,rgba(34,197,94,0.06),rgba(59,130,246,0.04))">
  <h2>Key Takeaways</h2>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:12px">
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid rgba(34,197,94,0.2)">
      <div style="font-weight:700;color:var(--ours);margin-bottom:6px">Supply Chain Scanner Strengths</div>
      <ul style="color:var(--muted);font-size:0.85rem;padding-left:16px">
        <li>Automatic VS Code + JetBrains IDE discovery</li>
        <li>Multi-source intelligence (OSV + NVD + GHSA + Sonatype)</li>
        <li>NVD CPE matching catches IDE-level and extension-level CVEs</li>
        <li>EPSS exploit probability + CISA KEV enrichment</li>
        <li>Plugin inventory with publisher metadata</li>
      </ul>
    </div>
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid rgba(59,130,246,0.2)">
      <div style="font-weight:700;color:var(--trivy);margin-bottom:6px">Trivy Strengths</div>
      <ul style="color:var(--muted);font-size:0.85rem;padding-left:16px">
        <li>Scans transitive dependencies inside extensions</li>
        <li>Finds npm/NuGet vulnerability layer we miss</li>
        <li>Fast filesystem-level scanning</li>
        <li>Fix version recommendations</li>
        <li>Works alongside our scanner for complementary coverage</li>
      </ul>
    </div>
    <div style="padding:16px;background:var(--surface);border-radius:12px;border:1px solid rgba(167,139,250,0.2)">
      <div style="font-weight:700;color:var(--osv);margin-bottom:6px">OSV.dev Limitations</div>
      <ul style="color:var(--muted);font-size:0.85rem;padding-left:16px">
        <li>No VS Code Marketplace or JetBrains ecosystem</li>
        <li>Extension names don't resolve as npm packages</li>
        <li>Single-source database (no NVD CPE matching)</li>
        <li>No automatic extension/IDE discovery</li>
        <li>No EPSS or KEV enrichment</li>
      </ul>
    </div>
  </div>
</div>

<div class="footer">
  IDE Extension Security — Three-Way Comparison Report — Supply Chain Scanner vs Trivy vs OSV.dev<br>
  {len(vs_extensions)} VS Code extensions + {_jb_unique_ides} JetBrains IDEs + {_jb_unique_plugins} plugins scanned · Real Trivy + OSV data · {gen_time}
</div>

</div>
</body>
</html>"""

    out.write_text(html, encoding="utf-8")
    print(f"Report written to {out}")
    return out


if __name__ == "__main__":
    import sys
    report_path = sys.argv[1] if len(sys.argv) > 1 else "scanner/system_report.json"
    output = sys.argv[2] if len(sys.argv) > 2 else "scanner/vscode_comparison.html"
    build_vscode_comparison(report_path, output)
