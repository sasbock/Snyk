"""Writes the aggregate SBOM and VEX documents to disk (FR-10).

Only CycloneDX+JSON documents exist to write, since merge_sboms/derive_vex
only produce one for that format combination today -- an XML or SPDX
--sbom-format run has nothing here to write yet (its skip reason was
already reported by the merge/VEX steps).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_SBOM_BASENAME = "sbom"
DEFAULT_VEX_BASENAME = "vex"


@dataclass(frozen=True)
class WriteResult:
    sbom_path: Optional[Path] = None
    vex_path: Optional[Path] = None


def _output_path(output_prefix: Optional[str], basename: str, extension: str) -> Path:
    """FR-10's default is "both named ... (default: sbom/vex in the working directory)".

    Without --output-prefix, files are literally "sbom.<ext>"/"vex.<ext>"
    in the cwd. With one, e.g. --output-prefix ./out/run1, files become
    "./out/run1.sbom.<ext>"/"./out/run1.vex.<ext>" -- the prefix is a
    filename stem (its own directory must already exist), not just a
    directory.
    """
    if not output_prefix:
        return Path(f"{basename}.{extension}")
    return Path(f"{output_prefix}.{basename}.{extension}")


def write_outputs(
    sbom_document: Optional[dict],
    vex_document: Optional[dict],
    output_prefix: Optional[str],
) -> WriteResult:
    """Writes whichever of the aggregate SBOM/VEX documents were produced.

    A document that wasn't produced (merge/VEX skipped for this run's
    format or state) is simply not written -- this function never
    fabricates a placeholder file.
    """
    sbom_path = None
    if sbom_document is not None:
        sbom_path = _output_path(output_prefix, DEFAULT_SBOM_BASENAME, "json")
        sbom_path.write_text(json.dumps(sbom_document, indent=2) + "\n", encoding="utf-8")
        logger.debug("wrote aggregate SBOM to %s", sbom_path)

    vex_path = None
    if vex_document is not None:
        vex_path = _output_path(output_prefix, DEFAULT_VEX_BASENAME, "json")
        vex_path.write_text(json.dumps(vex_document, indent=2) + "\n", encoding="utf-8")
        logger.debug("wrote aggregate VEX to %s", vex_path)

    return WriteResult(sbom_path=sbom_path, vex_path=vex_path)
