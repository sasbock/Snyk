"""Fetches (FR-7) and merges (FR-8) per-project SBOM documents.

Per FR-1, only projects classified in-scope (Open Source/Container --
see resolvers/base.py) are fetched; others are skipped and logged in
debug mode rather than attempted. Per FR-14, a single project's fetch
failure is reported and the run continues by default; --fail-fast
aborts the whole run on the first one instead.

Merging (merge_sboms) is implemented for CycloneDX+JSON only -- the
format FR-7/FR-8 describe concretely. XML and SPDX SBOMs are still
fetched, but merging them is out of scope for now (each has a
meaningfully different merge story: XML needs its own parser, and SPDX
uses packages/relationships rather than components/dependencies) and is
reported back as a skip reason rather than attempted.

VEX derivation (FR-9) and writing output files (FR-10) are still not
implemented.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .errors import ProjectFetchError, SnykCraSbomVexError
from .resolvers.base import ResolvedProject
from .snyk_api.client import SnykClient

logger = logging.getLogger(__name__)

TOOL_NAME = "snyk-generate-cra-sbom-vex"
TOOL_VERSION = "0.1.0"


@dataclass(frozen=True)
class SbomFetchResult:
    project: ResolvedProject
    ok: bool
    document: Optional[bytes] = None
    item_count: Optional[int] = None  # components (CycloneDX) or packages (SPDX), if countable
    error: Optional[str] = None


def _count_items(raw: bytes, sbom_format: str) -> Optional[int]:
    if "+json" not in sbom_format:
        return None  # XML formats aren't parsed here; fetch-only, not merge
    try:
        document = json.loads(raw)
    except ValueError:
        return None
    key = "packages" if sbom_format.startswith("spdx") else "components"
    items = document.get(key)
    return len(items) if isinstance(items, list) else None


def fetch_sboms(
    client: SnykClient,
    projects: List[ResolvedProject],
    sbom_format: str,
    fail_fast: bool = False,
) -> List[SbomFetchResult]:
    """Fetches the SBOM for every in-scope project in `projects`.

    Raises ProjectFetchError immediately if fail_fast is set and a fetch
    fails; otherwise records the failure in the returned list and moves
    on to the next project (FR-14).
    """
    results: List[SbomFetchResult] = []

    for project in projects:
        if not project.in_scope:
            logger.debug(
                "skipping SBOM fetch for %s/%s (type=%s, not Open Source/Container per FR-1)",
                project.org_id,
                project.project_id,
                project.project_type,
            )
            continue

        try:
            document = client.get_project_sbom(project.org_id, project.project_id, sbom_format)
        except SnykCraSbomVexError as exc:
            document = None
            error = str(exc)
        else:
            error = None if document is not None else "Snyk SBOM API returned 404 for this project"

        if error is not None:
            logger.error(
                "SBOM fetch failed for %s/%s (%s): %s",
                project.org_id,
                project.project_id,
                project.name,
                error,
            )
            if fail_fast:
                raise ProjectFetchError(
                    f"SBOM fetch failed for {project.org_id}/{project.project_id}: {error}"
                )
            results.append(SbomFetchResult(project=project, ok=False, error=error))
            continue

        item_count = _count_items(document, sbom_format)
        logger.debug(
            "fetched SBOM for %s/%s (%s): %d bytes%s",
            project.org_id,
            project.project_id,
            project.name,
            len(document),
            f", {item_count} item(s)" if item_count is not None else "",
        )
        results.append(SbomFetchResult(project=project, ok=True, document=document, item_count=item_count))

    return results


# -- merge (FR-8) -----------------------------------------------------------

_CYCLONEDX_JSON_FORMAT_RE = re.compile(r"^cyclonedx(?P<spec_version>\d+\.\d+)\+json$")
_UNION_LIST_FIELDS = ("licenses", "hashes", "externalReferences")


@dataclass(frozen=True)
class MergeResult:
    document: Optional[Dict[str, Any]]
    component_count: int
    raw_component_count: int  # sum across sources, before purl-level de-duplication
    dependency_count: int
    # (org_id, project_id, package_name, package_version) -> canonical ref in
    # `document`, so vex.py can point a project's issues at the right merged
    # component without re-deriving _dedup_key itself.
    component_lookup: Dict[Tuple[str, str, str, str], str]
    skipped_reason: Optional[str] = None


def _dedup_key(component: Dict[str, Any]) -> str:
    """The identity a component is merged on: its purl, or a structural fallback.

    Not every component carries a purl -- a Container project's root
    `metadata.component` (the scanned image itself) typically doesn't --
    so those fall back to (type, group, name, version), which still lets
    identical images/components pulled in by different projects collapse
    into one entry.
    """
    purl = component.get("purl")
    if purl:
        return purl
    parts = (
        component.get("type", ""),
        component.get("group", ""),
        component.get("name", ""),
        component.get("version", ""),
    )
    return "no-purl:" + "|".join(parts)


def _dedup_json_list(items: List[Any]) -> List[Any]:
    seen: Set[str] = set()
    result: List[Any] = []
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _merge_component_into(
    store: Dict[str, Dict[str, Any]], canonical_ref: str, component: Dict[str, Any], project: ResolvedProject
) -> None:
    """Adds/merges one source component into the aggregate, under its canonical ref.

    FR-8: identical components collapse into one entry with merged
    properties noting every contributing project, and merged
    licenses/hashes/externalReferences rather than only the first seen.
    A `snyk:sourceProjectId` property is what makes each component
    traceable back to its originating project (NFR-1).
    """
    provenance = {"name": "snyk:sourceProjectId", "value": f"{project.org_id}/{project.project_id}"}
    existing = store.get(canonical_ref)

    if existing is None:
        merged = copy.deepcopy(component)
        merged["bom-ref"] = canonical_ref
        merged["properties"] = list(merged.get("properties", [])) + [provenance]
        store[canonical_ref] = merged
        return

    for field_name in _UNION_LIST_FIELDS:
        if field_name in component:
            existing[field_name] = _dedup_json_list(existing.get(field_name, []) + component[field_name])

    properties = existing.setdefault("properties", [])
    if provenance not in properties:
        properties.append(provenance)


def merge_sboms(fetch_results: List[SbomFetchResult], sbom_format: str) -> MergeResult:
    """Merges every successfully fetched SBOM into one aggregate CycloneDX document.

    Components are de-duplicated by _dedup_key (FR-8); the dependency
    graph is rebuilt on top of that same de-duplication, since each
    source document's bom-refs are only locally unique (two projects can
    both label their nth component "n-<name>@<version>", which would
    silently corrupt the merged edges if left unmapped) -- so bom-refs
    are remapped to the canonical ref before edges are unioned.
    """
    format_match = _CYCLONEDX_JSON_FORMAT_RE.match(sbom_format)
    if format_match is None:
        return MergeResult(
            document=None,
            component_count=0,
            raw_component_count=0,
            dependency_count=0,
            component_lookup={},
            skipped_reason=(
                f"merging is only implemented for CycloneDX+JSON formats; the "
                f"{sbom_format} SBOMs already fetched were not merged (FR-8)."
            ),
        )

    successful = [r for r in fetch_results if r.ok and r.document]
    if not successful:
        return MergeResult(
            document=None,
            component_count=0,
            raw_component_count=0,
            dependency_count=0,
            component_lookup={},
            skipped_reason="no successfully fetched SBOMs to merge",
        )

    merged_components: Dict[str, Dict[str, Any]] = {}
    merged_edges: Dict[str, Set[str]] = defaultdict(set)
    component_lookup: Dict[Tuple[str, str, str, str], str] = {}
    raw_component_count = 0

    for result in successful:
        try:
            source_doc = json.loads(result.document)
        except ValueError:
            logger.warning(
                "could not parse SBOM for %s/%s as JSON; excluded from merge",
                result.project.org_id,
                result.project.project_id,
            )
            continue

        local_components = list(source_doc.get("components") or [])
        root_component = (source_doc.get("metadata") or {}).get("component")
        if root_component:
            local_components = [root_component] + local_components
        raw_component_count += len(local_components)

        local_ref_map: Dict[str, str] = {}
        for component in local_components:
            canonical_ref = _dedup_key(component)
            local_bom_ref = component.get("bom-ref")
            if local_bom_ref:
                local_ref_map[local_bom_ref] = canonical_ref
            name, version = component.get("name"), component.get("version")
            if name and version:
                component_lookup[(result.project.org_id, result.project.project_id, name, version)] = canonical_ref
            _merge_component_into(merged_components, canonical_ref, component, result.project)

        for dependency in source_doc.get("dependencies") or []:
            ref = local_ref_map.get(dependency.get("ref"), dependency.get("ref"))
            if ref is None:
                continue
            depends_on = {local_ref_map.get(d, d) for d in dependency.get("dependsOn") or []}
            merged_edges[ref].update(depends_on)

    components = [merged_components[key] for key in sorted(merged_components)]
    dependencies = [
        {"ref": ref, "dependsOn": sorted(deps)} for ref, deps in sorted(merged_edges.items())
    ]

    spec_version = format_match.group("spec_version")
    document = {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        # A fresh serialNumber/timestamp per run is normal CycloneDX practice
        # (they identify *this* BOM generation) and doesn't conflict with
        # NFR-2's idempotency goal, which is about component/dependency
        # *ordering* being stable so diffs stay meaningful -- both are sorted
        # by canonical ref above for exactly that reason.
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"services": [{"provider": {"name": "Snyk"}, "name": TOOL_NAME, "version": TOOL_VERSION}]},
        },
        "components": components,
        "dependencies": dependencies,
    }

    return MergeResult(
        document=document,
        component_count=len(components),
        raw_component_count=raw_component_count,
        dependency_count=len(dependencies),
        component_lookup=component_lookup,
    )
