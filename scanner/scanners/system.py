from __future__ import annotations

import json
import platform
import plistlib
import re
import shutil
import subprocess
from pathlib import Path

from scanner.core.sbom import Component, build_component

BREW_OSV_ALIASES = {
    # Go ecosystem
    "kubernetes-cli": {"osv_ecosystem": "Go", "osv_name": "k8s.io/kubernetes"},
    "trivy": {"osv_ecosystem": "Go", "osv_name": "github.com/aquasecurity/trivy"},
    # PyPI ecosystem
    "azure-cli": {"osv_ecosystem": "PyPI", "osv_name": "azure-cli"},
    "python@3.10": {"osv_ecosystem": "PyPI", "osv_name": "cpython"},
    "python@3.11": {"osv_ecosystem": "PyPI", "osv_name": "cpython"},
    "python@3.12": {"osv_ecosystem": "PyPI", "osv_name": "cpython"},
    # Maven ecosystem
    "maven": {"osv_ecosystem": "Maven", "osv_name": "org.apache.maven:maven-core"},
    "openjdk": {"osv_ecosystem": "Maven", "osv_name": "org.openjdk:openjdk"},
    # NuGet ecosystem
    "dotnet-sdk": {"osv_ecosystem": "NuGet", "osv_name": "Microsoft.NETCore.App.Runtime"},
    # OSS-Fuzz / C/C++ libraries
    "openssl@3": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "openssl"},
    "sqlite": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "sqlite3"},
    "harfbuzz": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "harfbuzz"},
    "freetype": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "freetype2"},
    "icu4c": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "icu"},
    "libpng": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libpng"},
    "libtiff": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libtiff"},
    "zstd": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "zstd"},
    "pcre2": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "pcre2"},
    "xz": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "xzutils"},
    "lz4": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "lz4"},
    "cairo": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "cairo"},
    "jpeg-turbo": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libjpeg-turbo"},
    "jq": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "jq"},
    "oniguruma": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "oniguruma"},
    "glib": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "glib"},
    "little-cms2": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "lcms"},
    "giflib": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "giflib"},
    "fontconfig": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "fontconfig"},
    "pixman": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "pixman"},
    "libxcb": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libxcb"},
    "ncurses": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "ncurses"},
    "git": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "git"},
    "lynx": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "lynx"},
    "graphite2": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "graphite"},
    "lzo": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "lzo"},
    # Additional system libraries
    "ca-certificates": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "ca-certificates"},
    "gdbm": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "gdbm"},
    "gettext": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "gettext"},
    "readline": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "readline"},
    "libx11": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libx11"},
    "libxau": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libxau"},
    "libxdmcp": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libxdmcp"},
    "libxext": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libxext"},
    "libxrender": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "libxrender"},
    "mpdecimal": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "mpdecimal"},
    "xorgproto": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "xorgproto"},
    "watch": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "procps-ng"},
    "ghostty": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "ghostty"},
    # Browsers
    "google-chrome": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
    "chromium": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
    "firefox": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "firefox"},
    "microsoft-edge": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
    "brave-browser": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
}


def scan_system_packages() -> list[Component]:
    system_name = platform.system()
    components: list[Component] = []

    if system_name == "Darwin":
        components.extend(_scan_homebrew())
        components.extend(_scan_macos_applications())
    elif system_name == "Windows":
        components.extend(_scan_windows())
    elif system_name == "Linux":
        if shutil.which("dpkg"):
            components.extend(_scan_dpkg())
        elif shutil.which("rpm"):
            components.extend(_scan_rpm())
    components.extend(_scan_developer_toolchains())
    deduped: dict[tuple[str, str, str], Component] = {}
    for component in components:
        key = (component.name.lower(), component.version, component.ecosystem)
        deduped[key] = component
    return list(deduped.values())


def _scan_dpkg() -> list[Component]:
    result = subprocess.run(
        ["dpkg", "-l"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
    )
    if result.returncode != 0:
        return []

    components: list[Component] = []
    for line in result.stdout.splitlines():
        if not line.startswith("ii"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        components.append(
            build_component(
                name=parts[1],
                version=parts[2],
                ecosystem="os",
                component_type="system",
                source="dpkg",
                metadata={"package_manager": "dpkg", "osv_ecosystem": "Debian"},
            )
        )
    return components


MACOS_APP_ALIASES: dict[str, dict[str, str]] = {
    "Google Chrome": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
    "Chromium": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
    "Firefox": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "firefox"},
    "Microsoft Edge": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
    "Brave Browser": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "chromium"},
    "Visual Studio Code": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "vscode"},
    "Docker Desktop": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "docker"},
    "Postman": {"osv_ecosystem": "npm", "osv_name": "postman"},
}


def _scan_macos_applications() -> list[Component]:
    app_roots = [Path("/Applications"), Path.home() / "Applications"]
    components: list[Component] = []
    for app_root in app_roots:
        if not app_root.exists():
            continue
        for app_dir in app_root.glob("*.app"):
            info_plist = app_dir / "Contents" / "Info.plist"
            if not info_plist.exists():
                continue
            try:
                with info_plist.open("rb") as fh:
                    info = plistlib.load(fh)
            except Exception:  # noqa: BLE001
                continue
            app_name = str(
                info.get("CFBundleDisplayName")
                or info.get("CFBundleName")
                or app_dir.stem
            ).strip()
            app_version = str(
                info.get("CFBundleShortVersionString")
                or info.get("CFBundleVersion")
                or "unknown"
            ).strip()
            metadata = {
                "platform": "macos",
                "package_manager": "app_bundle",
            }
            metadata.update(MACOS_APP_ALIASES.get(app_name, {}))
            components.append(
                build_component(
                    name=app_name,
                    version=app_version,
                    ecosystem="os",
                    component_type="application",
                    source=str(app_dir),
                    metadata=metadata,
                )
            )
    return components


_CLI_TOOL_PROBES: list[tuple[str, str, list[str], dict[str, str]]] = [
    ("docker", "docker", ["docker", "--version"], {"osv_ecosystem": "OSS-Fuzz", "osv_name": "docker"}),
    ("docker-compose", "docker-compose", ["docker-compose", "--version"], {"osv_ecosystem": "OSS-Fuzz", "osv_name": "docker"}),
    ("kubectl", "kubernetes-cli", ["kubectl", "version", "--client", "--short"], {"osv_ecosystem": "Go", "osv_name": "k8s.io/kubernetes"}),
    ("node", "nodejs", ["node", "--version"], {"osv_ecosystem": "npm", "osv_name": "node"}),
    ("npm", "npm", ["npm", "--version"], {"osv_ecosystem": "npm", "osv_name": "npm"}),
    ("yarn", "yarn", ["yarn", "--version"], {"osv_ecosystem": "npm", "osv_name": "yarn"}),
    ("pnpm", "pnpm", ["pnpm", "--version"], {"osv_ecosystem": "npm", "osv_name": "pnpm"}),
    ("python3", "python3", ["python3", "--version"], {"osv_ecosystem": "PyPI", "osv_name": "cpython"}),
    ("pip3", "pip", ["pip3", "--version"], {"osv_ecosystem": "PyPI", "osv_name": "pip"}),
    ("java", "openjdk", ["java", "-version"], {"osv_ecosystem": "Maven", "osv_name": "org.openjdk:openjdk"}),
    ("mvn", "maven", ["mvn", "-version"], {"osv_ecosystem": "Maven", "osv_name": "org.apache.maven:maven-core"}),
    ("gradle", "gradle", ["gradle", "--version"], {"osv_ecosystem": "Maven", "osv_name": "gradle"}),
    ("go", "golang", ["go", "version"], {"osv_ecosystem": "Go", "osv_name": "golang.org/x/tools"}),
    ("rustc", "rust", ["rustc", "--version"], {"osv_ecosystem": "crates.io", "osv_name": "rust"}),
    ("cargo", "cargo", ["cargo", "--version"], {"osv_ecosystem": "crates.io", "osv_name": "cargo"}),
    ("dotnet", "dotnet-sdk", ["dotnet", "--version"], {"osv_ecosystem": "NuGet", "osv_name": "Microsoft.NETCore.App.Runtime"}),
    ("trivy", "trivy", ["trivy", "--version"], {"osv_ecosystem": "Go", "osv_name": "github.com/aquasecurity/trivy"}),
]


def _scan_developer_toolchains() -> list[Component]:
    components: list[Component] = []
    for binary, component_name, command, alias in _CLI_TOOL_PROBES:
        if not shutil.which(binary):
            continue
        version = _probe_version(command)
        if not version:
            continue
        metadata = {
            "package_manager": "cli_probe",
            "platform": platform.system().lower(),
            "binary": binary,
        }
        metadata.update(alias)
        components.append(
            build_component(
                name=component_name,
                version=version,
                ecosystem="os",
                component_type="application",
                source="cli_probe",
                metadata=metadata,
            )
        )
    return components


def _probe_version(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    output = f"{result.stdout}\n{result.stderr}".strip()
    if not output:
        return ""
    first_line = output.splitlines()[0]
    match = re.search(r"\d+(?:\.\d+){1,3}(?:[-+._][A-Za-z0-9]+)?", first_line)
    return match.group(0) if match else ""


def _scan_rpm() -> list[Component]:
    result = subprocess.run(
        ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
    )
    if result.returncode != 0:
        return []

    components: list[Component] = []
    for line in result.stdout.splitlines():
        if not line.strip() or "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="os",
                component_type="system",
                source="rpm",
                metadata={"package_manager": "rpm", "osv_ecosystem": "Red Hat"},
            )
        )
    return components


def _scan_homebrew() -> list[Component]:
    if not shutil.which("brew"):
        return []

    components = []
    components.extend(_scan_homebrew_list(["brew", "list", "--versions"], package_kind="formula"))
    components.extend(_scan_homebrew_list(["brew", "list", "--cask", "--versions"], package_kind="cask"))
    return components


def _scan_homebrew_list(command: list[str], *, package_kind: str) -> list[Component]:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
    )
    if result.returncode != 0:
        return []

    components: list[Component] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        versions = parts[1:]
        for version in versions:
            metadata = {
                "package_manager": "brew",
                "package_kind": package_kind,
                "platform": "macos",
            }
            metadata.update(BREW_OSV_ALIASES.get(name, {}))
            components.append(
                build_component(
                    name=name,
                    version=version,
                    ecosystem="os",
                    component_type="system",
                    source="brew",
                    metadata=metadata,
                )
            )
    return components


# ---------------------------------------------------------------------------
# Windows: Chocolatey, winget, and PowerShell registry fallback
# ---------------------------------------------------------------------------

WINDOWS_OSV_ALIASES: dict[str, dict[str, str]] = {
    # NuGet / .NET
    "dotnet-sdk": {"osv_ecosystem": "NuGet", "osv_name": "Microsoft.NETCore.App.Runtime"},
    "dotnet-runtime": {"osv_ecosystem": "NuGet", "osv_name": "Microsoft.NETCore.App.Runtime"},
    "dotnet-aspnetcore-runtime": {"osv_ecosystem": "NuGet", "osv_name": "Microsoft.AspNetCore.App.Runtime"},
    # Go ecosystem
    "kubernetes-cli": {"osv_ecosystem": "Go", "osv_name": "k8s.io/kubernetes"},
    "trivy": {"osv_ecosystem": "Go", "osv_name": "github.com/aquasecurity/trivy"},
    # PyPI ecosystem
    "python": {"osv_ecosystem": "PyPI", "osv_name": "cpython"},
    "python3": {"osv_ecosystem": "PyPI", "osv_name": "cpython"},
    "azure-cli": {"osv_ecosystem": "PyPI", "osv_name": "azure-cli"},
    # Maven ecosystem
    "maven": {"osv_ecosystem": "Maven", "osv_name": "org.apache.maven:maven-core"},
    "openjdk": {"osv_ecosystem": "Maven", "osv_name": "org.openjdk:openjdk"},
    "temurin": {"osv_ecosystem": "Maven", "osv_name": "org.openjdk:openjdk"},
    "corretto": {"osv_ecosystem": "Maven", "osv_name": "org.openjdk:openjdk"},
    # npm ecosystem
    "nodejs": {"osv_ecosystem": "npm", "osv_name": "node"},
    "nodejs.install": {"osv_ecosystem": "npm", "osv_name": "node"},
    # OSS-Fuzz / C/C++
    "openssl": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "openssl"},
    "git": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "git"},
    "git.install": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "git"},
    "curl": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "curl"},
    "sqlite": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "sqlite3"},
    "cmake": {"osv_ecosystem": "PyPI", "osv_name": "cmake"},
    "7zip": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "7-zip"},
    "7zip.install": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "7-zip"},
    "ffmpeg": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "ffmpeg"},
    "imagemagick": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "imagemagick"},
    "vim": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "vim"},
    "neovim": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "neovim"},
    "wget": {"osv_ecosystem": "OSS-Fuzz", "osv_name": "wget2"},
}


def _scan_windows() -> list[Component]:
    components: list[Component] = []
    components.extend(_scan_chocolatey())
    components.extend(_scan_winget())
    if not components:
        components.extend(_scan_windows_registry())
    return components


def _scan_chocolatey() -> list[Component]:
    if not shutil.which("choco"):
        return []

    result = subprocess.run(
        ["choco", "list", "--local-only", "--limit-output"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
    )
    if result.returncode != 0:
        return []

    components: list[Component] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        if not name or not version:
            continue
        metadata: dict[str, str] = {
            "package_manager": "chocolatey",
            "platform": "windows",
        }
        metadata.update(WINDOWS_OSV_ALIASES.get(name.lower(), {}))
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="os",
                component_type="system",
                source="chocolatey",
                metadata=metadata,
            )
        )
    return components


def _scan_winget() -> list[Component]:
    if not shutil.which("winget"):
        return []

    result = subprocess.run(
        ["winget", "list", "--disable-interactivity", "--accept-source-agreements"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        timeout=60,
    )
    if result.returncode != 0:
        return []

    components: list[Component] = []
    lines = result.stdout.splitlines()

    # Find the header separator line (contains dashes)
    header_idx = -1
    for idx, line in enumerate(lines):
        if line.strip().startswith("-") and "--" in line:
            header_idx = idx
            break
    if header_idx < 0 or header_idx < 1:
        return []

    # Parse column positions from the header line
    header_line = lines[header_idx - 1]
    name_end = header_line.lower().find("id")
    if name_end < 0:
        name_end = 0
    id_end = header_line.lower().find("version")
    if id_end < 0:
        return []
    version_end = header_line.lower().find("available", id_end + 1)
    if version_end < 0:
        version_end = header_line.lower().find("source", id_end + 1)
    if version_end < 0:
        version_end = len(header_line)

    for line in lines[header_idx + 1 :]:
        if not line.strip() or len(line) < id_end:
            continue
        pkg_id = line[name_end:id_end].strip()
        version = line[id_end:version_end].strip()
        if not pkg_id or not version:
            continue
        # Derive a short name from the package ID (e.g. "Git.Git" -> "git")
        short_name = pkg_id.rsplit(".", 1)[-1].lower() if "." in pkg_id else pkg_id.lower()
        metadata: dict[str, str] = {
            "package_manager": "winget",
            "package_id": pkg_id,
            "platform": "windows",
        }
        metadata.update(WINDOWS_OSV_ALIASES.get(short_name, {}))
        components.append(
            build_component(
                name=short_name,
                version=version,
                ecosystem="os",
                component_type="system",
                source="winget",
                metadata=metadata,
            )
        )
    return components


def _scan_windows_registry() -> list[Component]:
    """Fallback: query installed programs from Windows registry via PowerShell."""
    if not shutil.which("powershell"):
        return []

    ps_script = (
        "Get-ItemProperty "
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Where-Object { $_.DisplayName -and $_.DisplayVersion } "
        "| Select-Object DisplayName, DisplayVersion, Publisher "
        "| ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_script],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        timeout=60,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []

    components: list[Component] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("DisplayName") or "").strip()
        version = str(entry.get("DisplayVersion") or "").strip()
        publisher = str(entry.get("Publisher") or "").strip()
        if not name or not version:
            continue
        short_name = name.lower().replace(" ", "-")
        metadata: dict[str, str] = {
            "package_manager": "registry",
            "platform": "windows",
        }
        if publisher:
            metadata["publisher"] = publisher
        metadata.update(WINDOWS_OSV_ALIASES.get(short_name, {}))
        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="os",
                component_type="system",
                source="registry",
                metadata=metadata,
            )
        )
    return components