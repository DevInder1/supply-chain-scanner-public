from __future__ import annotations

from pathlib import Path

from scanner.core.extractor import load_json
from scanner.core.sbom import Component, build_component


def scan_vscode_extensions(base_path: str | None = None) -> list[Component]:
    extensions_path = Path(base_path or "~/.vscode/extensions").expanduser()
    if not extensions_path.exists():
        return []

    components: list[Component] = []
    for extension_dir in extensions_path.iterdir():
        package_path = extension_dir / "package.json"
        if not package_path.exists():
            continue
        try:
            package_data = load_json(package_path)
        except (OSError, ValueError):
            continue

        name = str(package_data.get("name") or extension_dir.name)
        version = str(package_data.get("version") or "unknown")
        publisher = str(package_data.get("publisher") or _publisher_from_dir(extension_dir.name))

        components.append(
            build_component(
                name=name,
                version=version,
                ecosystem="vscode",
                component_type="extension",
                source=str(package_path),
                metadata={"publisher": publisher},
            )
        )
    return components


def _publisher_from_dir(directory_name: str) -> str:
    if "." in directory_name:
        return directory_name.split(".", 1)[0]
    return "unknown"