from __future__ import annotations

import re
from typing import Any

from .sbom import Component

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

RANK_TO_SEVERITY = {
    4: "CRITICAL",
    3: "HIGH",
    2: "MEDIUM",
    1: "LOW",
    0: "UNKNOWN",
}

VERSION_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
VERSION_PREFIX_RE = re.compile(r"^[\^~<>=\s]*(\d[\w.+-]*)")


def match_components(
    components: list[Component],
    advisories_by_component: dict[tuple[str, str], list[dict[str, Any]]],
    epss_lookup: dict[str, dict[str, Any]] | None = None,
    kev_lookup: dict[str, dict[str, Any]] | None = None,
    nvd_lookup: dict[str, list[dict[str, Any]]] | None = None,
    ghsa_lookup: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
    ossindex_lookup: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    epss_lookup = epss_lookup or {}
    kev_lookup = kev_lookup or {}
    nvd_lookup = nvd_lookup or {}
    ghsa_lookup = ghsa_lookup or {}
    ossindex_lookup = ossindex_lookup or {}
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    # Track CVEs per component for multi-source confidence
    cve_sources: dict[tuple[str, str, str], set[str]] = {}  # (comp, ver, cve) -> {sources}

    for component in components:
        advisories = advisories_by_component.get((component.name.lower(), component.ecosystem), [])
        for advisory in advisories:
            if not advisory_matches_component(advisory, component):
                continue

            dedupe_key = (
                component.name.lower(),
                component.version,
                component.ecosystem,
                str(advisory.get("id", "UNKNOWN")),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            cve = advisory_cve(advisory)
            severity = normalize_severity(extract_severity(advisory))
            epss = epss_lookup.get(cve, {}) if cve else {}
            kev = kev_lookup.get(cve, {}) if cve else {}

            if cve:
                source_key = (component.name.lower(), component.version, cve)
                cve_sources.setdefault(source_key, set()).add("osv")

            findings.append(
                {
                    "component": component.to_dict(),
                    "advisory_id": advisory.get("id", "UNKNOWN"),
                    "cve": cve,
                    "summary": advisory.get("summary", ""),
                    "details": advisory.get("details", ""),
                    "severity": severity,
                    "epss": epss.get("score"),
                    "kev": bool(kev),
                    "final_risk": compute_final_risk(severity, epss.get("score"), bool(kev)),
                    "references": advisory.get("references", []),
                    "aliases": advisory.get("aliases", []),
                    "fix_versions": _extract_fix_versions(advisory),
                    "sources": ["osv"],
                }
            )

    # --- Merge NVD findings ---
    _merge_nvd_findings(
        findings, seen, cve_sources, nvd_lookup, components, epss_lookup, kev_lookup,
    )
    # --- Merge GHSA findings ---
    _merge_ghsa_findings(
        findings, seen, cve_sources, ghsa_lookup, components, epss_lookup, kev_lookup,
    )
    # --- Merge OSS Index findings ---
    _merge_ossindex_findings(
        findings, seen, cve_sources, ossindex_lookup, components, epss_lookup, kev_lookup,
    )

    # --- Compute confidence from multi-source agreement ---
    _apply_source_confidence(findings, cve_sources)

    findings.sort(
        key=lambda item: (
            -SEVERITY_RANK.get(item["final_risk"], 0),
            item["component"]["name"].lower(),
            item["advisory_id"],
        )
    )
    return findings


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        level = finding["final_risk"].lower()
        if level in summary:
            summary[level] += 1
    return summary


def advisory_matches_component(advisory: dict[str, Any], component: Component) -> bool:
    affected = advisory.get("affected", [])
    if not affected:
        return False

    expected_names = {component.name.lower()}
    alias_name = str(component.metadata.get("osv_name", "")).lower()
    if alias_name:
        expected_names.add(alias_name)

    for affected_entry in affected:
        package = affected_entry.get("package", {})
        package_name = str(package.get("name", "")).lower()
        if package_name and package_name not in expected_names:
            continue

        ecosystem = package.get("ecosystem")
        if ecosystem and not ecosystem_matches(component, str(ecosystem)):
            continue

        if version_matches(component.version, affected_entry):
            return True

    return False


def ecosystem_matches(component: Component, advisory_ecosystem: str) -> bool:
    advisory_value = advisory_ecosystem.lower()
    alias_ecosystem = str(component.metadata.get("osv_ecosystem", "")).lower()
    if alias_ecosystem:
        return advisory_value == alias_ecosystem
    if component.ecosystem == "npm":
        return advisory_value == "npm"
    if component.ecosystem == "os":
        expected = str(component.metadata.get("osv_ecosystem", "")).lower()
        return not expected or advisory_value == expected
    if component.ecosystem == "vscode":
        return advisory_value == "npm"
    if component.ecosystem == "jetbrains":
        return advisory_value in {"maven", "github actions"}
    return advisory_value == component.ecosystem.lower()


def version_matches(component_version: str, affected_entry: dict[str, Any]) -> bool:
    normalized_version = normalize_version(component_version)
    if not normalized_version:
        return False

    explicit_versions = affected_entry.get("versions", [])
    if normalized_version in explicit_versions or component_version in explicit_versions:
        return True
    # Handle prefixed versions like "jq-1.8.1" in OSS-Fuzz version lists
    if explicit_versions:
        for v in explicit_versions:
            stripped = _strip_version_prefix(v)
            if stripped == normalized_version:
                return True
        # If there's an explicit version list and our version isn't in it, not affected
        return False

    ranges = affected_entry.get("ranges", [])
    if not ranges:
        return False

    all_git = True
    for range_block in ranges:
        range_type = range_block.get("type", "")
        events = range_block.get("events", [])
        if not events:
            continue
        if range_type == "GIT":
            # GIT ranges use commit hashes — can't do semver comparison.
            # If no fixed event, still affected. Otherwise ambiguous.
            has_fixed = any("fixed" in e for e in events)
            if not has_fixed:
                return True
            continue
        all_git = False
        if evaluate_range_events(normalized_version, events):
            return True

    # If all ranges are GIT-only (commit hashes) and no explicit version list,
    # we can't determine version exclusion — treat as potentially affected
    if all_git and ranges:
        return True
    return False


def _strip_version_prefix(version_str: str) -> str:
    """Strip non-numeric prefix from version string (e.g. 'jq-1.8.1' -> '1.8.1')."""
    match = VERSION_PREFIX_RE.search(version_str)
    return match.group(1) if match else version_str


def evaluate_range_events(version: str, events: list[dict[str, str]]) -> bool:
    introduced = None
    affected = False

    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
            affected = introduced in {"0", "*"} or compare_versions(version, introduced) >= 0
        elif "fixed" in event:
            fixed = event["fixed"]
            if affected and compare_versions(version, fixed) < 0:
                return True
            affected = False
        elif "last_affected" in event:
            last_affected = event["last_affected"]
            if affected and compare_versions(version, last_affected) <= 0:
                return True
            affected = False
        elif "limit" in event:
            limit = event["limit"]
            if affected and compare_versions(version, limit) < 0:
                return True

    if affected:
        return True

    if introduced and introduced not in {"0", "*"}:
        return compare_versions(version, introduced) >= 0
    return False


def extract_severity(advisory: dict[str, Any]) -> str:
    # Check database_specific.severity first (GHSA uses this reliably)
    database_specific = advisory.get("database_specific", {})
    db_severity = database_specific.get("severity")
    if db_severity:
        normalized = str(db_severity).upper().strip()
        if normalized == "MODERATE":
            return "MEDIUM"
        if normalized in SEVERITY_RANK:
            return normalized

    # Try CVSS vector string parsing
    severity_entries = advisory.get("severity", [])
    for item in severity_entries:
        score = item.get("score", "")
        score_upper = score.upper()
        if "CRITICAL" in score_upper:
            return "CRITICAL"
        if "HIGH" in score_upper:
            return "HIGH"
        if "MEDIUM" in score_upper or "MODERATE" in score_upper:
            return "MEDIUM"
        if "LOW" in score_upper:
            return "LOW"
        # Parse CVSS v3 base score from vector
        if score_upper.startswith("CVSS:"):
            cvss_severity = _severity_from_cvss_vector(score)
            if cvss_severity:
                return cvss_severity

    return "UNKNOWN"


def _severity_from_cvss_vector(vector: str) -> str | None:
    """Estimate severity from CVSS v3 vector metrics."""
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    # Use Attack Vector + Confidentiality/Integrity/Availability impact as rough estimate
    high_impacts = sum(
        1 for m in ("C", "I", "A") if metrics.get(m, "N").upper() == "H"
    )
    priv_required = metrics.get("PR", "N").upper()
    attack_vector = metrics.get("AV", "N").upper()

    if high_impacts >= 3 and priv_required == "N":
        return "CRITICAL"
    if high_impacts >= 2:
        return "HIGH"
    if high_impacts >= 1:
        return "MEDIUM"
    if attack_vector == "N":
        return "LOW"
    return None


def normalize_severity(value: str | None) -> str:
    normalized = str(value or "UNKNOWN").upper()
    return normalized if normalized in SEVERITY_RANK else "UNKNOWN"


def advisory_cve(advisory: dict[str, Any]) -> str | None:
    aliases = advisory.get("aliases", [])
    for alias in aliases:
        if str(alias).startswith("CVE-"):
            return str(alias)
    advisory_id = str(advisory.get("id", ""))
    if advisory_id.startswith("CVE-"):
        return advisory_id
    return None


def compute_final_risk(severity: str, epss_score: float | None, kev: bool) -> str:
    rank = SEVERITY_RANK.get(normalize_severity(severity), 0)
    if epss_score is not None:
        if epss_score >= 0.7:
            rank += 1
        elif epss_score >= 0.3:
            rank = max(rank, 3)
    if kev:
        rank += 1
    return RANK_TO_SEVERITY[min(rank, 4)]


def _extract_fix_versions(advisory: dict[str, Any]) -> list[str]:
    """Extract fixed versions from advisory range events."""
    fixed: list[str] = []
    seen: set[str] = set()
    for affected_entry in advisory.get("affected", []):
        for range_block in affected_entry.get("ranges", []):
            for event in range_block.get("events", []):
                version = event.get("fixed", "")
                if version and version not in seen:
                    seen.add(version)
                    fixed.append(version)
    return fixed


def normalize_version(version: str) -> str:
    value = version.strip()
    if not value:
        return ""
    match = VERSION_PREFIX_RE.match(value)
    if match:
        return match.group(1)
    return value


def compare_versions(left: str, right: str) -> int:
    left_tokens = tokenize_version(left)
    right_tokens = tokenize_version(right)

    max_len = max(len(left_tokens), len(right_tokens))
    for index in range(max_len):
        left_token = left_tokens[index] if index < len(left_tokens) else (0, 0)
        right_token = right_tokens[index] if index < len(right_tokens) else (0, 0)
        if left_token == right_token:
            continue
        return -1 if left_token < right_token else 1
    return 0


def tokenize_version(version: str) -> list[tuple[int, str | int]]:
    tokens = VERSION_TOKEN_RE.findall(normalize_version(version))
    parsed: list[tuple[int, str | int]] = []
    for token in tokens:
        if token.isdigit():
            parsed.append((0, int(token)))
        else:
            parsed.append((1, token.lower()))
    return parsed


# ---------------------------------------------------------------------------
# Multi-source merge helpers
# ---------------------------------------------------------------------------

def _merge_nvd_findings(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
    cve_sources: dict[tuple[str, str, str], set[str]],
    nvd_lookup: dict[str, list[dict[str, Any]]],
    components: list["Component"],
    epss_lookup: dict[str, dict[str, Any]],
    kev_lookup: dict[str, dict[str, Any]],
) -> None:
    from scanner.sources.nvd import map_cpe
    for component in components:
        cpe = map_cpe(component)
        if not cpe:
            continue
        nvd_cves = nvd_lookup.get(component.name.lower(), [])
        for cve_entry in nvd_cves:
            cve_id = cve_entry.get("cve_id") or cve_entry.get("id", "")
            dedupe_key = (component.name.lower(), component.version, component.ecosystem, cve_id)
            source_key = (component.name.lower(), component.version, cve_id)

            if dedupe_key in seen:
                # Already exists from OSV — just add source tag
                cve_sources.setdefault(source_key, set()).add("nvd")
                for f in findings:
                    if (f["component"]["name"].lower() == component.name.lower()
                            and f["component"]["version"] == component.version
                            and f.get("cve") == cve_id):
                        if "nvd" not in f.get("sources", []):
                            f.setdefault("sources", []).append("nvd")
                        # Upgrade severity if NVD has a better (non-UNKNOWN) score
                        nvd_sev = normalize_severity(cve_entry.get("severity"))
                        if nvd_sev != "UNKNOWN" and f["severity"] == "UNKNOWN":
                            f["severity"] = nvd_sev
                            f["final_risk"] = compute_final_risk(
                                nvd_sev, f.get("epss"), f.get("kev", False)
                            )
                        if cve_entry.get("cvss_score") and not f.get("cvss_score"):
                            f["cvss_score"] = cve_entry["cvss_score"]
                        break
                continue

            seen.add(dedupe_key)
            cve_sources.setdefault(source_key, set()).add("nvd")
            epss = epss_lookup.get(cve_id, {})
            kev = kev_lookup.get(cve_id, {})
            severity = normalize_severity(cve_entry.get("severity", "UNKNOWN"))

            findings.append({
                "component": component.to_dict(),
                "advisory_id": cve_id,
                "cve": cve_id,
                "summary": cve_entry.get("summary", ""),
                "details": "",
                "severity": severity,
                "cvss_score": cve_entry.get("cvss_score"),
                "epss": epss.get("score"),
                "kev": bool(kev),
                "final_risk": compute_final_risk(severity, epss.get("score"), bool(kev)),
                "references": cve_entry.get("references", []),
                "aliases": [],
                "fix_versions": [],
                "sources": ["nvd"],
            })


def _merge_ghsa_findings(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
    cve_sources: dict[tuple[str, str, str], set[str]],
    ghsa_lookup: dict[tuple[str, str], list[dict[str, Any]]],
    components: list["Component"],
    epss_lookup: dict[str, dict[str, Any]],
    kev_lookup: dict[str, dict[str, Any]],
) -> None:
    from scanner.sources.ghsa import map_ghsa_package_name, supports_ghsa_query
    for component in components:
        if not supports_ghsa_query(component):
            continue
        pkg_name = map_ghsa_package_name(component).lower()
        osv_eco = str(component.metadata.get("osv_ecosystem", component.ecosystem))
        ghsa_advs = ghsa_lookup.get((pkg_name, osv_eco), [])
        for adv in ghsa_advs:
            ghsa_id = adv.get("ghsa_id") or adv.get("id", "")
            cve_id = adv.get("cve")
            dedupe_key = (component.name.lower(), component.version, component.ecosystem, ghsa_id)

            # Check if we already have this CVE from another source
            if cve_id:
                for f in findings:
                    if (f.get("cve") == cve_id
                            and f["component"]["name"].lower() == component.name.lower()
                            and f["component"]["version"] == component.version):
                        if "ghsa" not in f.get("sources", []):
                            f.setdefault("sources", []).append("ghsa")
                        source_key = (component.name.lower(), component.version, cve_id)
                        cve_sources.setdefault(source_key, set()).add("ghsa")
                        # Upgrade severity if current is UNKNOWN
                        ghsa_sev = normalize_severity(adv.get("severity"))
                        if ghsa_sev != "UNKNOWN" and f["severity"] == "UNKNOWN":
                            f["severity"] = ghsa_sev
                            f["final_risk"] = compute_final_risk(
                                ghsa_sev, f.get("epss"), f.get("kev", False)
                            )
                        if adv.get("cvss_score") and not f.get("cvss_score"):
                            f["cvss_score"] = adv["cvss_score"]
                        # Add fix version from GHSA if available
                        fix_v = adv.get("fix_version")
                        if fix_v and fix_v not in f.get("fix_versions", []):
                            f.setdefault("fix_versions", []).append(fix_v)
                        dedupe_key = None  # skip adding new finding
                        break

            if dedupe_key is None or dedupe_key in seen:
                continue

            # Check version is in vulnerable range
            vuln_range = adv.get("vulnerable_range", "")
            if vuln_range and not _ghsa_version_in_range(component.version, vuln_range):
                continue

            seen.add(dedupe_key)
            if cve_id:
                source_key = (component.name.lower(), component.version, cve_id)
                cve_sources.setdefault(source_key, set()).add("ghsa")

            epss = epss_lookup.get(cve_id, {}) if cve_id else {}
            kev = kev_lookup.get(cve_id, {}) if cve_id else {}
            severity = normalize_severity(adv.get("severity", "UNKNOWN"))
            fix_versions = [adv["fix_version"]] if adv.get("fix_version") else []

            findings.append({
                "component": component.to_dict(),
                "advisory_id": ghsa_id,
                "cve": cve_id,
                "summary": adv.get("summary", ""),
                "details": "",
                "severity": severity,
                "cvss_score": adv.get("cvss_score"),
                "epss": epss.get("score"),
                "kev": bool(kev),
                "final_risk": compute_final_risk(severity, epss.get("score"), bool(kev)),
                "references": adv.get("references", []),
                "aliases": [],
                "fix_versions": fix_versions,
                "sources": ["ghsa"],
            })


def _merge_ossindex_findings(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
    cve_sources: dict[tuple[str, str, str], set[str]],
    ossindex_lookup: dict[str, list[dict[str, Any]]],
    components: list["Component"],
    epss_lookup: dict[str, dict[str, Any]],
    kev_lookup: dict[str, dict[str, Any]],
) -> None:
    from scanner.sources.ossindex import build_purl
    for component in components:
        purl = build_purl(component)
        if not purl:
            continue
        oss_vulns = ossindex_lookup.get(purl, [])
        for vuln in oss_vulns:
            vuln_id = vuln.get("id") or vuln.get("reference", "")
            cve_id = vuln.get("cve")
            dedupe_key = (component.name.lower(), component.version, component.ecosystem, vuln_id)

            # Merge into existing finding if CVE already known
            if cve_id:
                merged = False
                for f in findings:
                    if (f.get("cve") == cve_id
                            and f["component"]["name"].lower() == component.name.lower()
                            and f["component"]["version"] == component.version):
                        if "sonatype" not in f.get("sources", []):
                            f.setdefault("sources", []).append("sonatype")
                        source_key = (component.name.lower(), component.version, cve_id)
                        cve_sources.setdefault(source_key, set()).add("sonatype")
                        merged = True
                        break
                if merged:
                    continue

            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            if cve_id:
                source_key = (component.name.lower(), component.version, cve_id)
                cve_sources.setdefault(source_key, set()).add("sonatype")

            epss = epss_lookup.get(cve_id, {}) if cve_id else {}
            kev = kev_lookup.get(cve_id, {}) if cve_id else {}
            severity = normalize_severity(vuln.get("severity", "UNKNOWN"))

            findings.append({
                "component": component.to_dict(),
                "advisory_id": vuln_id if vuln_id else (cve_id or "UNKNOWN"),
                "cve": cve_id,
                "summary": vuln.get("summary", ""),
                "details": vuln.get("details", ""),
                "severity": severity,
                "cvss_score": vuln.get("cvss_score"),
                "epss": epss.get("score"),
                "kev": bool(kev),
                "final_risk": compute_final_risk(severity, epss.get("score"), bool(kev)),
                "references": vuln.get("references", []),
                "aliases": [],
                "fix_versions": [],
                "sources": ["sonatype"],
            })


def _apply_source_confidence(
    findings: list[dict[str, Any]],
    cve_sources: dict[tuple[str, str, str], set[str]],
) -> None:
    """Set source_count and confidence on each finding based on multi-source agreement."""
    for finding in findings:
        cve = finding.get("cve")
        comp = finding.get("component", {})
        if cve:
            key = (comp.get("name", "").lower(), comp.get("version", ""), cve)
            sources = cve_sources.get(key, set())
            all_sources = sorted(sources)
            finding["sources"] = all_sources
            finding["source_count"] = len(all_sources)
            if len(all_sources) >= 3:
                finding["confidence"] = "high"
            elif len(all_sources) == 2:
                finding["confidence"] = "medium"
            else:
                finding["confidence"] = "low"
        else:
            finding.setdefault("sources", finding.get("sources", ["unknown"]))
            finding["source_count"] = len(finding["sources"])
            finding["confidence"] = "low"


def _ghsa_version_in_range(version: str, vuln_range: str) -> bool:
    """Check if a version satisfies a GHSA vulnerable version range like '>= 1.0, < 2.5'."""
    normalized = normalize_version(version)
    if not normalized:
        return True  # Can't determine — assume affected

    for constraint in vuln_range.split(","):
        constraint = constraint.strip()
        if not constraint:
            continue
        if constraint.startswith(">="):
            bound = constraint[2:].strip()
            if compare_versions(normalized, bound) < 0:
                return False
        elif constraint.startswith(">"):
            bound = constraint[1:].strip()
            if compare_versions(normalized, bound) <= 0:
                return False
        elif constraint.startswith("<="):
            bound = constraint[2:].strip()
            if compare_versions(normalized, bound) > 0:
                return False
        elif constraint.startswith("<"):
            bound = constraint[1:].strip()
            if compare_versions(normalized, bound) >= 0:
                return False
        elif constraint.startswith("="):
            bound = constraint[1:].strip()
            if compare_versions(normalized, bound) != 0:
                return False
    return True