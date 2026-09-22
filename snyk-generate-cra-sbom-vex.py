#!/usr/bin/env python3
"""Entry point for the Snyk CRA SBOM/VEX generator.

Per FR-16, this file is a thin shim: argument parsing is delegated to
snyk_generate_cra_sbom_vex.cli, and it holds no SBOM/VEX business logic
of its own -- only logging setup and top-level error-handling/exit-code
logic (FR-14).

This build implements source resolution/discovery (FR-2, FR-2a, FR-6)
and prints the resulting project list. SBOM fetch/merge, VEX
derivation, and file output (FR-7 onward) are not implemented yet.
"""

from __future__ import annotations

import sys
from typing import List, Optional

from snyk_generate_cra_sbom_vex import cli, config, discovery, logging_setup, reporting
from snyk_generate_cra_sbom_vex.errors import SnykCraSbomVexError
from snyk_generate_cra_sbom_vex.snyk_api.client import SnykClient


def main(argv: Optional[List[str]] = None) -> int:
    args = cli.parse_args(argv)

    # Configure logging before the token is known so any error raised
    # while resolving it is still reported (nothing sensitive can reach
    # the log at this point, since we never log args.token directly).
    logger = logging_setup.configure(debug=args.debug)

    try:
        run_config = config.build_config(args)
    except SnykCraSbomVexError as exc:
        logger.error(str(exc))
        return exc.exit_code

    # Re-configure now that the token is known, so every subsequent log
    # line has it redacted (FR-5, NFR-3).
    logger = logging_setup.configure(debug=run_config.debug, redact=[run_config.token])

    if run_config.vex_skip_reason:
        logger.warning(run_config.vex_skip_reason)

    sources = run_config.sources
    logger.info(
        "Resolving %d source argument(s): %d org, %d target, %d asset, %d project, "
        "%d group, %d tag...",
        sources.count(),
        len(sources.orgs),
        len(sources.targets),
        len(sources.assets),
        len(sources.projects),
        len(sources.groups),
        len(sources.tags),
    )

    client = SnykClient(token=run_config.token, api_version=run_config.api_version)

    try:
        projects = discovery.discover(client, sources)
    except SnykCraSbomVexError as exc:
        logger.error(str(exc))
        return exc.exit_code

    in_scope_count = sum(1 for p in projects if p.in_scope)
    org_count = len({p.org_id for p in projects})
    logger.info(
        "Discovered %d unique project(s) across %d org(s): %d in-scope for SBOM/VEX "
        "(Open Source/Container), %d other type(s) (see requirements doc FR-1).",
        len(projects),
        org_count,
        in_scope_count,
        len(projects) - in_scope_count,
    )
    print(reporting.render_projects_table(projects), flush=True)

    logger.info(
        "SBOM fetch/merge, VEX derivation, and file output (FR-7 onward) are not "
        "implemented yet; this build stops after discovery."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
