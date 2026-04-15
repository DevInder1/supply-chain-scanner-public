from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    ecosystem: str
    type: str
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "type": self.type,
        }
        if self.source:
            payload["source"] = self.source
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


def build_component(
    name: str,
    version: str,
    ecosystem: str,
    component_type: str,
    *,
    source: str = "",
    metadata: dict[str, Any] | None = None,
) -> Component:
    return Component(
        name=name.strip(),
        version=str(version).strip(),
        ecosystem=ecosystem.strip(),
        type=component_type.strip(),
        source=source.strip(),
        metadata=metadata or {},
    )


def merge_components(*component_groups: list[Component]) -> list[Component]:
    deduped: dict[tuple[str, str, str, str], Component] = {}
    for group in component_groups:
        for component in group:
            key = (
                component.name.lower(),
                component.version,
                component.ecosystem,
                component.type,
            )
            deduped[key] = component
    return sorted(deduped.values(), key=lambda item: (item.ecosystem, item.name.lower(), item.version))


def export_sbom(components: list[Component]) -> list[dict[str, Any]]:
    return [component.to_dict() for component in components]