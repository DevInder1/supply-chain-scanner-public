from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


def read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def load_json(path: str | Path) -> dict[str, Any]:
    content = read_text(path)
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return data


def load_config(path: str | Path) -> dict[str, Any]:
    content = read_text(path)
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    try:
        data = ast.literal_eval(content)
        if isinstance(data, dict):
            return data
    except (SyntaxError, ValueError):
        pass

    return _parse_simple_yaml(content)


def expand_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def ensure_directory(path: str | Path) -> Path:
    directory = expand_path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def ensure_parent(path: str | Path) -> Path:
    target = expand_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _parse_simple_yaml(content: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any] | list[Any]]] = [(-1, root)]

    for raw_line in content.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]
        if line.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError("Invalid YAML list structure")
            parent.append(_coerce_scalar(line[2:].strip()))
            continue

        if ":" not in line:
            raise ValueError(f"Invalid config line: {raw_line}")

        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value:
            if not isinstance(parent, dict):
                raise ValueError("Invalid YAML mapping structure")
            parent[key] = _coerce_scalar(raw_value)
            continue

        next_container: dict[str, Any] | list[Any]
        next_container = {}
        if not isinstance(parent, dict):
            raise ValueError("Invalid YAML nesting")
        parent[key] = next_container
        stack.append((indent, next_container))

    _fix_empty_maps_to_lists(root)
    return root


def _fix_empty_maps_to_lists(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in list(value.items()):
            if child == {} and key.endswith("_paths"):
                value[key] = []
                continue
            _fix_empty_maps_to_lists(child)
    elif isinstance(value, list):
        for child in value:
            _fix_empty_maps_to_lists(child)


def _coerce_scalar(value: str) -> Any:
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() == "null":
        return None
    if value.startswith("[") and value.endswith("]"):
        return json.loads(value)
    if value.startswith("{") and value.endswith("}"):
        return json.loads(value)
    if value.isdigit():
        return int(value)
    try:
        return float(value)
    except ValueError:
        return value.strip('"')