"""Renders discovery/fetch/merge/VEX results, and the files written, for terminal output.

This module owns presentation only; writers.py does the actual file I/O.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .resolvers.base import ResolvedProject
from .sbom import MergeResult, SbomFetchResult
from .vex import VexBuildResult
from .writers import WriteResult

_PROJECTS_HEADERS = ("ORG", "PROJECT", "TYPE", "SCOPE", "NAME", "SOURCE(S)")
_SBOM_HEADERS = ("ORG", "PROJECT", "NAME", "STATUS", "ITEMS", "BYTES", "DETAIL")


def _render_table(headers: Sequence[str], rows: Sequence[Tuple[str, ...]]) -> str:
    if not rows:
        return "(none)"

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row: Tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    lines = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)


def render_projects_table(projects: List[ResolvedProject]) -> str:
    rows = [
        (
            p.org_id,
            p.project_id,
            p.project_type or "-",
            "in-scope" if p.in_scope else "skip",
            p.name or "-",
            p.source,
        )
        for p in projects
    ]
    return _render_table(_PROJECTS_HEADERS, rows)


def render_sbom_fetch_table(results: List[SbomFetchResult]) -> str:
    rows = []
    for r in results:
        rows.append(
            (
                r.project.org_id,
                r.project.project_id,
                r.project.name or "-",
                "ok" if r.ok else "FAILED",
                str(r.item_count) if r.item_count is not None else "-",
                str(len(r.document)) if r.document is not None else "-",
                "-" if r.ok else (r.error or ""),
            )
        )
    return _render_table(_SBOM_HEADERS, rows)


def render_merge_summary(result: MergeResult) -> str:
    if result.skipped_reason:
        return f"Merge skipped: {result.skipped_reason}"
    duplicates_collapsed = result.raw_component_count - result.component_count
    return (
        f"Merged {result.component_count} unique component(s) "
        f"({result.raw_component_count} raw across all fetched SBOMs, "
        f"{duplicates_collapsed} duplicate(s) collapsed by purl/identity), "
        f"{result.dependency_count} dependency edge(s). "
        f"serialNumber={result.document['serialNumber']}"
    )


def render_vex_summary(result: VexBuildResult) -> str:
    if result.skipped_reason:
        return f"VEX skipped: {result.skipped_reason}"
    warnings = []
    if result.needs_manual_justification:
        warnings.append(f"{result.needs_manual_justification} need manual justification (FR-4)")
    if result.unmatched_count:
        warnings.append(f"{result.unmatched_count} could not be matched to a merged SBOM component")
    suffix = f" ({'; '.join(warnings)})" if warnings else ""
    return f"Derived {result.vulnerability_count} VEX entry(ies){suffix}."


def render_write_summary(result: WriteResult) -> str:
    def describe(label: str, path: Optional[Path]) -> str:
        return f"{label}: {path}" if path is not None else f"{label}: (not written -- nothing to write)"

    return "\n".join([describe("SBOM", result.sbom_path), describe("VEX", result.vex_path)])
