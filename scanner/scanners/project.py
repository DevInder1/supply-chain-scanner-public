from __future__ import annotations

import logging
import re
from pathlib import Path

from defusedxml import ElementTree as ET
from scanner.core.extractor import load_json
from scanner.core.sbom import Component, build_component

log = logging.getLogger(__name__)


def _parse_requirements_txt(req_path: Path) -> list[Component]:
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*([<>=!~]{1,2})\s*([A-Za-z0-9_.+-]+)\s*$")
    for raw in req_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = pattern.match(line)
        if not match:
            continue
        name, operator, version = match.group(1), match.group(2), match.group(3)
        normalized_version = f"{operator}{version}"
        if not name or not version:
            continue
        ident = (name.lower(), normalized_version)
        if ident in seen:
            continue
        seen.add(ident)
        components.append(
            build_component(
                name=name,
                version=normalized_version,
                ecosystem="PyPI",
                component_type="project",
                source=str(req_path),
                metadata={"transitive": False, "specifier": operator},
            )
        )
    return components


def _parse_poetry_lock(lock_path: Path) -> list[Component]:
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    text = lock_path.read_text(encoding="utf-8", errors="replace")
    name: str | None = None
    version: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            version = line.split("=", 1)[1].strip().strip('"')
        elif line == "[[package]]":
            name = None
            version = None
        if name and version:
            ident = (name.lower(), version)
            if ident not in seen:
                seen.add(ident)
                components.append(
                    build_component(
                        name=name,
                        version=version,
                        ecosystem="PyPI",
                        component_type="project",
                        source=str(lock_path),
                        metadata={"transitive": True},
                    )
                )
            name = None
            version = None
    return components


def _parse_go_sum(go_sum_path: Path) -> list[Component]:
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    for raw in go_sum_path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = raw.strip().split()
        if len(parts) < 2:
            continue
        name = parts[0]
        version = parts[1]
        if version.endswith("/go.mod"):
            version = version[:-7]
        ident = (name.lower(), version)
        if ident in seen:
            continue
        seen.add(ident)
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="Go",
                component_type="project",
                source=str(go_sum_path),
                metadata={"transitive": True},
            )
        )
    return components


def _parse_cargo_lock(lock_path: Path) -> list[Component]:
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    text = lock_path.read_text(encoding="utf-8", errors="replace")
    name: str | None = None
    version: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            name = None
            version = None
            continue
        if line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            version = line.split("=", 1)[1].strip().strip('"')
        if name and version:
            ident = (name.lower(), version)
            if ident not in seen:
                seen.add(ident)
                components.append(
                    build_component(
                        name=name,
                        version=version,
                        ecosystem="crates.io",
                        component_type="project",
                        source=str(lock_path),
                        metadata={"transitive": True},
                    )
                )
            name = None
            version = None
    return components


def _parse_package_lock(lock_path: Path) -> list[Component]:
    """Parse package-lock.json (v2/v3) for resolved transitive dependencies."""
    data = load_json(lock_path)
    lock_version = data.get("lockfileVersion", 1)

    components: list[Component] = []
    seen: set[tuple[str, str]] = set()

    if lock_version >= 2:
        # v2/v3: use the "packages" map
        packages = data.get("packages", {})
        for key, info in packages.items():
            if not key:  # root entry
                continue
            # Extract the package name from the nested node_modules path
            name = key.replace("node_modules/", "").split("node_modules/")[-1]
            version = info.get("version", "")
            if not name or not version:
                continue
            ident = (name, version)
            if ident in seen:
                continue
            seen.add(ident)
            scope = "dev" if info.get("dev") else "production"
            components.append(
                build_component(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    component_type="project",
                    source=str(lock_path),
                    metadata={"scope": scope, "transitive": True},
                )
            )
    else:
        # v1: use the "dependencies" tree
        _walk_v1_deps(data.get("dependencies", {}), lock_path, seen, components)

    return components


def _walk_v1_deps(
    deps: dict,
    lock_path: Path,
    seen: set[tuple[str, str]],
    out: list[Component],
) -> None:
    """Recursively walk lockfile v1 dependency tree."""
    for name, info in deps.items():
        version = info.get("version", "")
        if not version:
            continue
        ident = (name, version)
        if ident in seen:
            continue
        seen.add(ident)
        scope = "dev" if info.get("dev") else "production"
        out.append(
            build_component(
                name=name,
                version=version,
                ecosystem="npm",
                component_type="project",
                source=str(lock_path),
                metadata={"scope": scope, "transitive": True},
            )
        )
        # Recurse into nested dependencies
        nested = info.get("dependencies", {})
        if nested:
            _walk_v1_deps(nested, lock_path, seen, out)


def _parse_yarn_lock(lock_path: Path) -> list[Component]:
    """Parse yarn.lock for resolved dependencies (classic format)."""
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    current_name = ""
    text = lock_path.read_text(encoding="utf-8", errors="replace")

    for line in text.splitlines():
        stripped = line.strip()
        # Entry headers look like: "package-name@^1.0.0":
        # or: "package-name@^1.0.0", "package-name@~2.0.0":
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":"):
            # New package entry — extract name from first specifier
            spec = stripped.rstrip(":").strip('"').split(",")[0].strip().strip('"')
            at_idx = spec.rfind("@")
            if at_idx > 0:
                current_name = spec[:at_idx]
        elif line.startswith("  version") and current_name:
            version = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1]
            ident = (current_name, version)
            if ident not in seen:
                seen.add(ident)
                components.append(
                    build_component(
                        name=current_name,
                        version=version,
                        ecosystem="npm",
                        component_type="project",
                        source=str(lock_path),
                        metadata={"scope": "unknown", "transitive": True},
                    )
                )
            current_name = ""

    return components


def _parse_pnpm_lock(lock_path: Path) -> list[Component]:
    """Parse pnpm-lock.yaml for resolved packages."""
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    text = lock_path.read_text(encoding="utf-8", errors="replace")

    in_packages = False
    for line in text.splitlines():
        # pnpm-lock v6+: "packages:" section with entries like /package@version:
        # pnpm-lock v9+: entries like package@version:
        if line.strip() == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" ") and not line.startswith("/"):
            in_packages = False
            continue
        if not in_packages:
            continue
        stripped = line.strip().rstrip(":")
        if not stripped or stripped.startswith("#"):
            continue
        # Match pnpm lockfile patterns: /name@version or name@version
        entry = stripped.lstrip("/").strip("'\"")
        at_idx = entry.rfind("@")
        if at_idx > 0:
            name = entry[:at_idx]
            version = entry[at_idx + 1:].split("(")[0]  # strip peer dep qualifiers
            if name and version:
                ident = (name, version)
                if ident not in seen:
                    seen.add(ident)
                    components.append(
                        build_component(
                            name=name,
                            version=version,
                            ecosystem="npm",
                            component_type="project",
                            source=str(lock_path),
                            metadata={"scope": "unknown", "transitive": True},
                        )
                    )

    return components


# ── .NET / NuGet parsers ──────────────────────────────────────────────

def _parse_nuget_lock(lock_path: Path) -> list[Component]:
    """Parse packages.lock.json (NuGet lock file)."""
    data = load_json(lock_path)
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()

    for framework, deps in data.get("dependencies", {}).items():
        if not isinstance(deps, dict):
            continue
        for name, info in deps.items():
            resolved = info.get("resolved", "") if isinstance(info, dict) else ""
            if not name or not resolved:
                continue
            ident = (name.lower(), resolved)
            if ident in seen:
                continue
            seen.add(ident)
            dep_type = info.get("type", "Direct") if isinstance(info, dict) else "Direct"
            components.append(
                build_component(
                    name=name,
                    version=resolved,
                    ecosystem="NuGet",
                    component_type="project",
                    source=str(lock_path),
                    metadata={"framework": framework, "transitive": dep_type == "Transitive"},
                )
            )
    return components


def _parse_csproj(csproj_path: Path) -> list[Component]:
    """Extract PackageReference items from a .csproj file."""
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    try:
        tree = ET.parse(csproj_path)  # noqa: S314 – trusted local files
    except ET.ParseError:
        log.warning("Failed to parse %s", csproj_path)
        return []

    for ref in tree.iter():
        if ref.tag.split("}")[-1] != "PackageReference":
            continue
        name = ref.get("Include") or ref.get("include") or ""
        version = ref.get("Version") or ref.get("version") or ""
        if not version:
            ver_el = ref.find("Version") or ref.find("version")
            version = (ver_el.text or "").strip() if ver_el is not None else ""
        if not name or not version:
            continue
        ident = (name.lower(), version)
        if ident in seen:
            continue
        seen.add(ident)
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="NuGet",
                component_type="project",
                source=str(csproj_path),
                metadata={"transitive": False},
            )
        )
    return components


def _parse_packages_config(config_path: Path) -> list[Component]:
    """Parse packages.config (legacy NuGet format)."""
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    try:
        tree = ET.parse(config_path)  # noqa: S314
    except ET.ParseError:
        log.warning("Failed to parse %s", config_path)
        return []

    for pkg in tree.iter("package"):
        name = pkg.get("id") or ""
        version = pkg.get("version") or ""
        if not name or not version:
            continue
        ident = (name.lower(), version)
        if ident in seen:
            continue
        seen.add(ident)
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="NuGet",
                component_type="project",
                source=str(config_path),
                metadata={"framework": pkg.get("targetFramework", ""), "transitive": False},
            )
        )
    return components


# ── Java / Maven+Gradle parsers ──────────────────────────────────────

def _parse_pom_xml(pom_path: Path) -> list[Component]:
    """Extract <dependency> entries from pom.xml."""
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    try:
        tree = ET.parse(pom_path)  # noqa: S314
    except ET.ParseError:
        log.warning("Failed to parse %s", pom_path)
        return []

    root = tree.getroot()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    for dep in root.iter(f"{ns}dependency"):
        group = (dep.find(f"{ns}groupId") is not None and dep.find(f"{ns}groupId").text) or ""
        artifact = (dep.find(f"{ns}artifactId") is not None and dep.find(f"{ns}artifactId").text) or ""
        version_el = dep.find(f"{ns}version")
        version = (version_el.text or "").strip() if version_el is not None else ""
        scope = (dep.find(f"{ns}scope") is not None and dep.find(f"{ns}scope").text) or "compile"

        if not group or not artifact or not version:
            continue
        # Skip Maven property placeholders like ${project.version}
        if version.startswith("${"):
            continue

        name = f"{group}:{artifact}"
        ident = (name.lower(), version)
        if ident in seen:
            continue
        seen.add(ident)
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="Maven",
                component_type="project",
                source=str(pom_path),
                metadata={"groupId": group, "artifactId": artifact, "scope": scope, "transitive": False},
            )
        )
    return components


def _parse_gradle_lockfile(lock_path: Path) -> list[Component]:
    """Parse gradle.lockfile or buildscript-gradle.lockfile."""
    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    text = lock_path.read_text(encoding="utf-8", errors="replace")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: group:artifact:version=configuration(s)
        parts = line.split("=")[0].strip().split(":")
        if len(parts) < 3:
            continue
        group, artifact, version = parts[0], parts[1], parts[2]
        if not group or not artifact or not version:
            continue
        name = f"{group}:{artifact}"
        ident = (name.lower(), version)
        if ident in seen:
            continue
        seen.add(ident)
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="Maven",
                component_type="project",
                source=str(lock_path),
                metadata={"groupId": group, "artifactId": artifact, "transitive": True},
            )
        )
    return components


def _parse_build_gradle(gradle_path: Path) -> list[Component]:
    """Best-effort extraction of dependencies from build.gradle / build.gradle.kts."""

    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    text = gradle_path.read_text(encoding="utf-8", errors="replace")

    # Match patterns like: implementation 'group:artifact:version'
    #   or: implementation("group:artifact:version")
    pattern = re.compile(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)"
        r"[\s(]+['\"]([^'\"]+:[^'\"]+:[^'\"]+)['\"]"
    )
    for match in pattern.finditer(text):
        parts = match.group(1).split(":")
        if len(parts) < 3:
            continue
        group, artifact, version = parts[0], parts[1], parts[2]
        if not version or version.startswith("$"):
            continue
        name = f"{group}:{artifact}"
        ident = (name.lower(), version)
        if ident in seen:
            continue
        seen.add(ident)
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="Maven",
                component_type="project",
                source=str(gradle_path),
                metadata={"groupId": group, "artifactId": artifact, "transitive": False},
            )
        )
    return components


# ── Main entry point ─────────────────────────────────────────────────

def scan_project_dependencies(
    project_path: str | None = None,
    *,
    exclude_dirs: list[str] | None = None,
) -> list[Component]:
    root = Path(project_path or ".").resolve()
    exclude_dirs = exclude_dirs or []
    project_roots = _discover_project_roots(root, exclude_dirs=exclude_dirs)
    all_components: list[Component] = []

    for project_root in project_roots:
        all_components.extend(_scan_single_project_root(project_root))

    if not all_components:
        log.warning("No supported project manifest found in %s", root)

    return all_components


def _scan_single_project_root(root: Path) -> list[Component]:
    all_components: list[Component] = []
    # ── npm ────────────────────────────────────────────────────────────
    package_json = root / "package.json"
    lock_file = root / "package-lock.json"
    yarn_lock = root / "yarn.lock"
    pnpm_lock = root / "pnpm-lock.yaml"

    if lock_file.exists():
        log.info("Parsing package-lock.json (%s) for resolved dependencies", lock_file)
        comps = _parse_package_lock(lock_file)
        if comps:
            log.info("Found %d resolved packages from package-lock.json", len(comps))
            all_components.extend(comps)
    elif yarn_lock.exists():
        log.info("Parsing yarn.lock (%s) for resolved dependencies", yarn_lock)
        comps = _parse_yarn_lock(yarn_lock)
        if comps:
            log.info("Found %d resolved packages from yarn.lock", len(comps))
            all_components.extend(comps)
    elif pnpm_lock.exists():
        log.info("Parsing pnpm-lock.yaml (%s) for resolved dependencies", pnpm_lock)
        comps = _parse_pnpm_lock(pnpm_lock)
        if comps:
            log.info("Found %d resolved packages from pnpm-lock.yaml", len(comps))
            all_components.extend(comps)
    elif package_json.exists():
        log.info("No lockfile found, falling back to package.json direct dependencies")
        package_data = load_json(package_json)
        for section_name in ("dependencies", "devDependencies"):
            section = package_data.get(section_name, {})
            if not isinstance(section, dict):
                continue
            for dependency_name, dependency_version in section.items():
                all_components.append(
                    build_component(
                        name=dependency_name,
                        version=str(dependency_version),
                        ecosystem="npm",
                        component_type="project",
                        source=str(package_json),
                        metadata={"scope": section_name},
                    )
                )

    # ── .NET / NuGet ──────────────────────────────────────────────────
    nuget_lock = root / "packages.lock.json"
    packages_config = root / "packages.config"
    csproj_files = list(root.rglob("*.csproj"))

    if nuget_lock.exists():
        log.info("Parsing packages.lock.json (%s)", nuget_lock)
        comps = _parse_nuget_lock(nuget_lock)
        if comps:
            log.info("Found %d NuGet packages from packages.lock.json", len(comps))
            all_components.extend(comps)
    elif csproj_files:
        for csproj in csproj_files:
            log.info("Parsing %s for PackageReference entries", csproj.name)
            comps = _parse_csproj(csproj)
            if comps:
                log.info("Found %d NuGet packages from %s", len(comps), csproj.name)
                all_components.extend(comps)
    elif packages_config.exists():
        log.info("Parsing packages.config (%s)", packages_config)
        comps = _parse_packages_config(packages_config)
        if comps:
            log.info("Found %d NuGet packages from packages.config", len(comps))
            all_components.extend(comps)

    # ── Java / Maven + Gradle ─────────────────────────────────────────
    pom_xml = root / "pom.xml"
    gradle_lock = root / "gradle.lockfile"
    build_gradle = root / "build.gradle"
    build_gradle_kts = root / "build.gradle.kts"

    if pom_xml.exists():
        log.info("Parsing pom.xml (%s)", pom_xml)
        comps = _parse_pom_xml(pom_xml)
        if comps:
            log.info("Found %d Maven packages from pom.xml", len(comps))
            all_components.extend(comps)

    if gradle_lock.exists():
        log.info("Parsing gradle.lockfile (%s)", gradle_lock)
        comps = _parse_gradle_lockfile(gradle_lock)
        if comps:
            log.info("Found %d packages from gradle.lockfile", len(comps))
            all_components.extend(comps)
    elif build_gradle.exists():
        log.info("Parsing build.gradle (%s)", build_gradle)
        comps = _parse_build_gradle(build_gradle)
        if comps:
            log.info("Found %d packages from build.gradle", len(comps))
            all_components.extend(comps)
    elif build_gradle_kts.exists():
        log.info("Parsing build.gradle.kts (%s)", build_gradle_kts)
        comps = _parse_build_gradle(build_gradle_kts)
        if comps:
            log.info("Found %d packages from build.gradle.kts", len(comps))
            all_components.extend(comps)

    # ── Python / Go / Rust ────────────────────────────────────────────
    requirements_txt = root / "requirements.txt"
    poetry_lock = root / "poetry.lock"
    go_sum = root / "go.sum"
    cargo_lock = root / "Cargo.lock"

    if poetry_lock.exists():
        log.info("Parsing poetry.lock (%s)", poetry_lock)
        comps = _parse_poetry_lock(poetry_lock)
        if comps:
            log.info("Found %d Python packages from poetry.lock", len(comps))
            all_components.extend(comps)
    elif requirements_txt.exists():
        log.info("Parsing requirements.txt (%s)", requirements_txt)
        comps = _parse_requirements_txt(requirements_txt)
        if comps:
            log.info("Found %d Python packages from requirements.txt", len(comps))
            all_components.extend(comps)

    if go_sum.exists():
        log.info("Parsing go.sum (%s)", go_sum)
        comps = _parse_go_sum(go_sum)
        if comps:
            log.info("Found %d Go modules from go.sum", len(comps))
            all_components.extend(comps)

    if cargo_lock.exists():
        log.info("Parsing Cargo.lock (%s)", cargo_lock)
        comps = _parse_cargo_lock(cargo_lock)
        if comps:
            log.info("Found %d Rust crates from Cargo.lock", len(comps))
            all_components.extend(comps)
    return all_components


def _discover_project_roots(root: Path, *, exclude_dirs: list[str]) -> list[Path]:
    markers = {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "packages.lock.json",
        "packages.config",
        "requirements.txt",
        "poetry.lock",
        "go.sum",
        "Cargo.lock",
    }
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".cursor"}
    normalized_excludes = {item.strip("/").strip() for item in exclude_dirs if item and item.strip()}
    roots: set[Path] = set()

    if any((root / marker).exists() for marker in markers):
        roots.add(root)

    def is_excluded(path: Path) -> bool:
        if any(part in skip_dirs for part in path.parts):
            return True
        if not normalized_excludes:
            return False
        try:
            rel_path = path.relative_to(root)
        except ValueError:
            return True
        rel_text = rel_path.as_posix()
        return any(
            rel_text == excluded
            or rel_text.startswith(f"{excluded}/")
            or excluded in rel_path.parts
            for excluded in normalized_excludes
        )

    for marker in markers:
        for marker_path in root.rglob(marker):
            if marker_path.is_symlink():
                continue
            parent = marker_path.parent
            if is_excluded(parent):
                continue
            roots.add(parent)
    discovered = sorted(roots)
    if discovered:
        log.info("Discovered %d project manifest root(s) under %s", len(discovered), root)
    return discovered or [root]