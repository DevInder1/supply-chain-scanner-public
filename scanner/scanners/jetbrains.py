from __future__ import annotations

import os
import re
from pathlib import Path
from zipfile import BadZipFile, ZipFile
from defusedxml import ElementTree

from scanner.core.sbom import Component, build_component

# Regex to extract IDE name and version from product directory names
# e.g. "WebStorm2024.1" → ("WebStorm", "2024.1")
_IDE_DIR_RE = re.compile(
    r"^(WebStorm|IntelliJIdea|IdeaIC|PyCharm(?:CE)?|CLion|GoLand|PhpStorm"
    r"|DataGrip|RubyMine|Rider|DataSpell|Fleet|Aqua|RustRover|Writerside)"
    r"(\d{4}\.\d+)$"
)

_IDE_DISPLAY_NAMES: dict[str, str] = {
    "WebStorm": "WebStorm",
    "IntelliJIdea": "IntelliJ IDEA",
    "IdeaIC": "IntelliJ IDEA Community",
    "PyCharm": "PyCharm",
    "PyCharmCE": "PyCharm Community",
    "CLion": "CLion",
    "GoLand": "GoLand",
    "PhpStorm": "PhpStorm",
    "DataGrip": "DataGrip",
    "RubyMine": "RubyMine",
    "Rider": "Rider",
    "DataSpell": "DataSpell",
    "Fleet": "Fleet",
    "Aqua": "Aqua",
    "RustRover": "RustRover",
    "Writerside": "Writerside",
}


def scan_jetbrains_plugins(base_paths: list[str] | None = None) -> list[Component]:
    candidates = base_paths or _default_jetbrains_paths()
    components: list[Component] = []
    seen_ides: set[tuple[str, str]] = set()

    for base_path in candidates:
        root = Path(base_path).expanduser()
        if not root.exists():
            continue
        for product_dir in root.iterdir():
            if not product_dir.is_dir():
                continue
            # Detect JetBrains IDE application from directory name
            m = _IDE_DIR_RE.match(product_dir.name)
            if m:
                ide_key, ide_version = m.group(1), m.group(2)
                ide_name = _IDE_DISPLAY_NAMES.get(ide_key, ide_key)
                if (ide_name, ide_version) not in seen_ides:
                    seen_ides.add((ide_name, ide_version))
                    components.append(build_component(
                        name=ide_name,
                        version=ide_version,
                        ecosystem="jetbrains",
                        component_type="application",
                        source=str(product_dir),
                    ))

            # Scan plugins inside this product directory
            plugins_dir = product_dir / "plugins"
            if not plugins_dir.exists():
                continue
            for plugin_dir in plugins_dir.iterdir():
                component = _parse_plugin(plugin_dir)
                if component:
                    components.append(component)
    return components


def _parse_plugin(plugin_dir: Path) -> Component | None:
    name = plugin_dir.stem if plugin_dir.is_file() else plugin_dir.name
    version = "unknown"

    if plugin_dir.is_dir():
        plugin_xml = plugin_dir / "META-INF" / "plugin.xml"
        if plugin_xml.exists():
            parsed_name, parsed_version = _parse_plugin_xml(plugin_xml.read_text(encoding="utf-8", errors="ignore"))
            if parsed_name:
                name = parsed_name
            if parsed_version:
                version = parsed_version
        else:
            # Most JetBrains plugins use lib/*.jar with plugin.xml inside
            parsed_name, parsed_version = _parse_lib_jars(plugin_dir)
            if not parsed_name:
                return None
            name = parsed_name
            if parsed_version:
                version = parsed_version
    elif plugin_dir.suffix.lower() in {".jar", ".zip"}:
        parsed_name, parsed_version = _parse_plugin_archive(plugin_dir)
        if not parsed_name and not parsed_version:
            return None
        if parsed_name:
            name = parsed_name
        if parsed_version:
            version = parsed_version
    else:
        return None

    return build_component(
        name=name,
        version=version,
        ecosystem="jetbrains",
        component_type="extension",
        source=str(plugin_dir),
    )


def _parse_lib_jars(plugin_dir: Path) -> tuple[str | None, str | None]:
    """Scan lib/*.jar inside a plugin directory for META-INF/plugin.xml."""
    lib_dir = plugin_dir / "lib"
    if not lib_dir.is_dir():
        return None, None
    for jar_path in lib_dir.glob("*.jar"):
        parsed_name, parsed_version = _parse_plugin_archive(jar_path)
        if parsed_name:
            return parsed_name, parsed_version
    return None, None


def _parse_plugin_archive(plugin_path: Path) -> tuple[str | None, str | None]:
    try:
        with ZipFile(plugin_path) as archive:
            if "META-INF/plugin.xml" not in archive.namelist():
                return None, None
            content = archive.read("META-INF/plugin.xml").decode("utf-8", errors="ignore")
            return _parse_plugin_xml(content)
    except (BadZipFile, KeyError, OSError):
        return None, None


def _parse_plugin_xml(content: str) -> tuple[str | None, str | None]:
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return None, None
    return root.findtext("name"), root.findtext("version")


def _default_jetbrains_paths() -> list[str]:
    paths = [
        "~/.local/share/JetBrains",
        "~/Library/Application Support/JetBrains",
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:
        paths.append(os.path.join(appdata, "JetBrains"))
    localappdata = os.environ.get("LOCALAPPDATA")
    if localappdata:
        paths.append(os.path.join(localappdata, "JetBrains"))
    return paths