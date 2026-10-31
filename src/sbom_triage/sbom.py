"""Parse a bounded subset of CycloneDX JSON without guessing package identities."""

import json
from dataclasses import asdict, dataclass
from typing import Any

from packageurl import PackageURL

MAX_BYTES = 5 * 1024 * 1024
MAX_COMPONENTS = 500
SUPPORTED_TYPES = {"pypi", "npm", "maven", "golang", "cargo", "nuget", "gem", "composer"}


@dataclass
class Component:
    ref: str
    name: str
    version: str
    purl: str | None
    issue: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def parse_sbom(raw: bytes | str) -> list[Component]:
    if len(raw.encode() if isinstance(raw, str) else raw) > MAX_BYTES:
        raise ValueError("SBOM exceeds the 5 MiB input limit.")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("Input must be valid UTF-8 JSON.") from exc
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("Expected a CycloneDX JSON object (bomFormat = CycloneDX).")
    if doc.get("specVersion") not in {"1.4", "1.5", "1.6", "1.7"}:
        raise ValueError("Supported CycloneDX specVersion values: 1.4, 1.5, 1.6, 1.7.")
    components: list[Component] = []
    refs: set[str] = set()

    def visit(items: Any, depth: int = 0) -> None:
        if not isinstance(items, list) or depth > 30:
            raise ValueError("components must be an array; nesting must not exceed 30 levels.")
        for item in items:
            if len(components) >= MAX_COMPONENTS:
                raise ValueError("SBOM exceeds the 500-component demo-tool limit.")
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise ValueError("Every component needs a string name.")
            name = item["name"].strip()
            if not name:
                raise ValueError("Component names cannot be empty.")
            version = item.get("version", "")
            if not isinstance(version, str):
                raise ValueError("Component version must be a string.")
            ref = item.get("bom-ref", f"component-{len(components) + 1}")
            if not isinstance(ref, str) or not ref or ref in refs:
                raise ValueError("bom-ref values must be unique, nonempty strings.")
            refs.add(ref)
            purl, issue = None, None
            try:
                supplied = item.get("purl")
                if not isinstance(supplied, str) or not supplied:
                    raise ValueError("Missing purl; package ecosystem cannot be inferred safely.")
                parsed = PackageURL.from_string(supplied)
                if parsed.type not in SUPPORTED_TYPES:
                    raise ValueError(
                        f"Unsupported purl type: {parsed.type}; needs another scanner."
                    )
                if parsed.version and version and parsed.version != version:
                    raise ValueError("Component version and purl version disagree.")
                version = parsed.version or version
                if not version:
                    raise ValueError("Missing exact package version.")
                purl = parsed._replace(version=version, subpath=None).to_string()
            except (ValueError, TypeError) as exc:
                issue = str(exc)
            components.append(Component(ref, name, version, purl, issue))
            visit(item.get("components", []), depth + 1)

    metadata = doc.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object.")
    if "component" in metadata:
        visit([metadata["component"]])
    visit(doc.get("components", []))
    return components
