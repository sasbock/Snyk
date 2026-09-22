"""Derives a CycloneDX VEX document from each project's issue/ignore data (FR-9, FR-3, FR-4).

Open Risk #2 asked which API is authoritative for ignore-reason
metadata. Confirmed against the live OpenAPI spec
(https://api.snyk.io/rest/openapi/{api-version}) while building this
module: the REST issues endpoint's `attributes.ignored` is only a
boolean, and its `relationships.ignore` is an opaque {id, type:
"ignore"} reference with no path in this API version to fetch the
ignore's actual reason/expiry. That detail is only available from the
legacy v1 `GET /v1/org/{org}/project/{project}/ignores` endpoint, keyed
by issue ID, in the reasonType/reason/expires shape FR-3's mapping
table is written against -- so this module reads the vulnerability list
from the REST API and ignore reasons from the legacy v1 API.

VEX entries are cross-referenced to the aggregate SBOM via
MergeResult.component_lookup (built while merging, from the same
project-scoped package name/version each issue's `coordinates` report),
so VEX can only be derived once an aggregate SBOM exists (FR-3: "only
CycloneDX+JSON" merges have one).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .sbom import MergeResult, SbomFetchResult
from .snyk_api.client import SnykClient

logger = logging.getLogger(__name__)

# CycloneDX's fixed vocabulary for analysis.justification -- it is a code,
# not free text (FR-4 explicitly warns against "guessing a justification
# code"), so a Snyk ignore comment is only used here when it already reads
# as one of these, never paraphrased or inferred.
_VALID_JUSTIFICATION_CODES = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}
_NON_ALNUM_RE = re.compile(r"[\s\-]+")


@dataclass(frozen=True)
class VexBuildResult:
    document: Optional[Dict[str, Any]]
    vulnerability_count: int
    needs_manual_justification: int  # FR-4: ignores flagged for manual review rather than guessed
    unmatched_count: int  # issues that couldn't be linked to a merged SBOM component
    skipped_reason: Optional[str] = None


def _normalize_justification_code(reason_text: str) -> Optional[str]:
    normalized = _NON_ALNUM_RE.sub("_", reason_text.strip().lower())
    return normalized if normalized in _VALID_JUSTIFICATION_CODES else None


def _extract_ignore_details(ignores_for_issue: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """Unwraps the legacy v1 shape: [{path_or_"*": details}, ...] -> details.

    A project can carry more than one ignore rule per issue (e.g. one per
    dependency path); this script isn't dependency-path-granular, so it
    takes the first rule as the project-level determination.
    """
    if not ignores_for_issue:
        return None
    first_entry = ignores_for_issue[0]
    if not isinstance(first_entry, dict) or not first_entry:
        return None
    return next(iter(first_entry.values()), None)


def _preferred_vuln_id(issue_attrs: Dict[str, Any]) -> str:
    for problem in issue_attrs.get("problems") or []:
        if problem.get("source") == "NVD" and str(problem.get("id", "")).startswith("CVE-"):
            return problem["id"]
    return issue_attrs.get("key") or ""


def _build_analysis(ignore_details: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], bool]:
    """Returns (analysis block, needs_manual_justification) per FR-3's table / FR-4."""
    if ignore_details is None:
        return {"state": "exploitable"}, False

    reason_type = ignore_details.get("reasonType")
    reason_text = (ignore_details.get("reason") or "").strip()

    if reason_type == "wont-fix":
        analysis = {"state": "exploitable", "response": ["will_not_fix"]}
        if reason_text:
            analysis["detail"] = reason_text
        return analysis, False

    if reason_type == "temporary-ignore":
        # CycloneDX's analysis object has no dedicated "review by" field, so
        # the ignore's expiry (FR-3: "must carry the ignore's expiry/review
        # date") is surfaced as free text in `detail` rather than forced
        # into a semantically mismatched field.
        expires = ignore_details.get("expires")
        detail_parts = [p for p in (f"Scheduled for review by {expires}." if expires else None, reason_text) if p]
        analysis = {"state": "in_triage"}
        if detail_parts:
            analysis["detail"] = " ".join(detail_parts)
        return analysis, False

    if reason_type == "not-vulnerable":
        justification_code = _normalize_justification_code(reason_text) if reason_text else None
        if justification_code is None:
            # FR-4: never fabricate a justification code from free text --
            # fall back to in_triage and flag for manual review instead.
            analysis = {"state": "in_triage"}
            if reason_text:
                analysis["detail"] = reason_text
            return analysis, True
        return {"state": "not_affected", "justification": justification_code, "detail": reason_text}, False

    # An ignore exists but with a reasonType FR-3's table doesn't cover (or
    # the ignore lookup found something structurally unexpected) -- treat
    # conservatively as needing manual review rather than guessing.
    return {"state": "in_triage"}, True


def _match_component_ref(
    issue_attrs: Dict[str, Any],
    component_lookup: Dict[Tuple[str, str, str, str], str],
    org_id: str,
    project_id: str,
) -> Optional[str]:
    for coordinate in issue_attrs.get("coordinates") or []:
        for representation in coordinate.get("representations") or []:
            dependency = representation.get("dependency") or {}
            name, version = dependency.get("package_name"), dependency.get("package_version")
            if name and version:
                ref = component_lookup.get((org_id, project_id, name, version))
                if ref:
                    return ref
    return None


def derive_vex(
    client: SnykClient,
    fetch_results: List[SbomFetchResult],
    merge_result: MergeResult,
    generate_vex: bool,
) -> VexBuildResult:
    """Builds the aggregate VEX document from every successfully fetched project's issues.

    Raises nothing project-specific: an issue that can't be matched to a
    merged component, or an ignore lacking a recognized justification, is
    counted and reported rather than treated as a fatal error (FR-14's
    "continue past a single project's failure" spirit extended to
    per-issue anomalies).
    """
    if not generate_vex:
        return VexBuildResult(
            document=None,
            vulnerability_count=0,
            needs_manual_justification=0,
            unmatched_count=0,
            skipped_reason="VEX generation disabled (--no-vex, or --sbom-format is not CycloneDX+JSON)",
        )

    if merge_result.document is None:
        return VexBuildResult(
            document=None,
            vulnerability_count=0,
            needs_manual_justification=0,
            unmatched_count=0,
            skipped_reason=(
                "no aggregate SBOM to cross-reference (merge was skipped: "
                f"{merge_result.skipped_reason})"
            ),
        )

    vulnerabilities: List[Dict[str, Any]] = []
    needs_manual = 0
    unmatched = 0

    for result in fetch_results:
        if not result.ok:
            continue
        project = result.project
        issues = client.list_project_issues(project.org_id, project.project_id)
        ignores = client.get_project_ignores(project.org_id, project.project_id)

        for issue in issues:
            attrs = issue.get("attributes") or {}
            if attrs.get("type") != "package_vulnerability":
                continue  # license/config/code findings aren't SBOM components (FR-1's scope, extended)

            component_ref = _match_component_ref(attrs, merge_result.component_lookup, project.org_id, project.project_id)
            if component_ref is None:
                unmatched += 1
                logger.debug(
                    "could not match issue %s in %s/%s to a merged SBOM component; skipped",
                    attrs.get("key"),
                    project.org_id,
                    project.project_id,
                )
                continue

            ignore_details = _extract_ignore_details(ignores.get(attrs.get("key")))
            analysis, needs_review = _build_analysis(ignore_details)
            if needs_review:
                needs_manual += 1
                logger.warning(
                    "manual justification required for %s in %s/%s: the ignore's reason "
                    "doesn't map to a recognized justification code, so in_triage was "
                    "emitted instead of not_affected (FR-4)",
                    attrs.get("key"),
                    project.org_id,
                    project.project_id,
                )

            vulnerabilities.append(
                {
                    "bom-ref": f"vuln-{issue.get('id')}",
                    "id": _preferred_vuln_id(attrs),
                    "affects": [{"ref": component_ref}],
                    "analysis": analysis,
                }
            )

    vulnerabilities.sort(key=lambda v: (v["id"], v["affects"][0]["ref"]))

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": merge_result.document["specVersion"],
        # Shared with the aggregate SBOM so a VEX consumer can cross-reference
        # the two documents as one unit (FR-3).
        "serialNumber": merge_result.document["serialNumber"],
        "version": 1,
        "vulnerabilities": vulnerabilities,
    }

    return VexBuildResult(
        document=document,
        vulnerability_count=len(vulnerabilities),
        needs_manual_justification=needs_manual,
        unmatched_count=unmatched,
    )
