"""Renders discovered-project results for terminal output.

This module owns presentation only; it does not write files -- that's
FR-10's job for writers.py, not yet implemented.
"""

from __future__ import annotations

from typing import List

from .resolvers.base import ResolvedProject

_HEADERS = ("ORG", "PROJECT", "TYPE", "SCOPE", "NAME", "SOURCE(S)")


def render_projects_table(projects: List[ResolvedProject]) -> str:
    if not projects:
        return "(no projects)"

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

    widths = [len(h) for h in _HEADERS]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row: tuple) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    lines = [fmt_row(_HEADERS), "  ".join("-" * w for w in widths)]
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)
