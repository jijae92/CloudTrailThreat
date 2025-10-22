"""IaC helper utilities for SAM/CloudFormation templates."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List

import yaml

from .fileio import ensure_path


class CloudFormationLoader(yaml.SafeLoader):
    """Safe loader that tolerates intrinsic function tags."""


def _construct_intrinsic(loader: CloudFormationLoader, tag_suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def load_template(path_str: str) -> Dict[str, object]:
    """Load a YAML or JSON template into a dictionary."""
    path = ensure_path(path_str)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".json"}:
        return json.loads(text)
    return yaml.load(text, Loader=CloudFormationLoader)


def find_resources(template: Dict[str, object], resource_type: str) -> List[Dict[str, object]]:
    """Return resources matching ``resource_type``."""
    resources = template.get("Resources", {}) if isinstance(template, dict) else {}
    matches: List[Dict[str, object]] = []
    for value in resources.values():
        if isinstance(value, dict) and value.get("Type") == resource_type:
            matches.append(value)
    return matches


def list_resource_types(template: Dict[str, object]) -> Iterable[str]:
    """Yield all resource types contained in the template."""
    resources = template.get("Resources", {}) if isinstance(template, dict) else {}
    for value in resources.values():
        if isinstance(value, dict) and "Type" in value:
            yield value["Type"]
