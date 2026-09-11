#!/usr/bin/env python3
"""
DISCLAIMER:
  This script is provided for demonstration, testing, and educational
  purposes only. It is NOT intended for production use. Use it at your
  own risk. The author assumes no responsibility or liability for any
  damage, data loss, or other consequences resulting from its use.

Delete inactive projects from a Snyk organization in bulk.

Uses the Snyk REST API:
  - GET    /rest/orgs/{org_id}/projects                 (list all projects, paginated)
  - DELETE /rest/orgs/{org_id}/projects/{project_id}     (delete a project)

Docs:
  https://apidocs.snyk.io/?version=2026-03-25#get-/orgs/-org_id-/projects
  https://apidocs.snyk.io/?version=2026-03-25#delete-/orgs/-org_id-/projects/-project_id-

Auth:
  Set SNYK_TOKEN in the environment, or pass --token.
  An  Org or Group Service Account token (snyk_sat.*). Either is sent as
  "Authorization: token <value>" The token's org/service-account role needs org admin
  permissions in the target organization to delete projects.

Example usage:
  # Preview what would be deleted (no changes made)
  SNYK_TOKEN=xxxx python3 snyk_delete_inactive_projects.py --org-id <org-id> --dry-run

  # Actually delete, with one bulk confirmation prompt for all of them
  SNYK_TOKEN=xxxx python3 snyk_delete_inactive_projects.py --org-id <org-id>

  # Confirm each project individually (y/n/a=yes-to-rest/q=stop)
  SNYK_TOKEN=xxxx python3 snyk_delete_inactive_projects.py --org-id <org-id> --per-project

  # Delete without prompting at all (e.g. for a scheduled cron job)
  SNYK_TOKEN=xxxx python3 snyk_delete_inactive_projects.py --org-id <org-id> --yes
"""

import argparse
import logging
import os
import sys
import time
from typing import Iterator

import requests

API_VERSION = "2026-03-25"
DEFAULT_BASE_URL = "https://api.snyk.io"
PAGE_LIMIT = 100  # API requires this to be a multiple of 10, minimum 10
MAX_RETRIES = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("snyk-cleanup")


def build_session(token: str) -> requests.Session:
    """Build a session authenticated with the "token" scheme (works for PATs
    and service account tokens)."""
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"token {token}",
            "Content-Type": "application/vnd.api+json",
        }
    )
    return session


def request_with_retries(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    """Issue a request, retrying on 429/5xx with exponential backoff."""
    for attempt in range(1, MAX_RETRIES + 1):
        resp = session.request(method, url, **kwargs)

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
            log.warning("Rate limited, retrying in %ss (attempt %s/%s)", retry_after, attempt, MAX_RETRIES)
            time.sleep(retry_after)
            continue

        if resp.status_code >= 500:
            backoff = 2 ** attempt
            log.warning(
                "Server error %s on %s, retrying in %ss (attempt %s/%s)",
                resp.status_code, url, backoff, attempt, MAX_RETRIES,
            )
            time.sleep(backoff)
            continue

        return resp

    resp.raise_for_status()
    return resp


def iter_inactive_projects(session: requests.Session, base_url: str, org_id: str) -> Iterator[dict]:
    """Yield inactive project resources for the org, following pagination cursors.

    See the module docstring for why filtering happens client-side here.
    """
    url = f"{base_url}/rest/orgs/{org_id}/projects"
    params = {
        "version": API_VERSION,
        "limit": PAGE_LIMIT,
    }

    while url:
        resp = request_with_retries(session, "GET", url, params=params)
        if resp.status_code != 200:
            log.error("Failed to list projects: %s %s", resp.status_code, resp.text)
            resp.raise_for_status()

        payload = resp.json()
        for project in payload.get("data", []):
            if project.get("attributes", {}).get("status") == "inactive":
                yield project

        next_link = payload.get("links", {}).get("next")
        if next_link:
            # 'next' is a full relative URL already containing query params.
            url = next_link if next_link.startswith("http") else f"{base_url}{next_link}"
            params = None
        else:
            url = None


def delete_project(session: requests.Session, base_url: str, org_id: str, project_id: str) -> bool:
    """Delete one project; returns True on success, False (after logging) on failure."""
    url = f"{base_url}/rest/orgs/{org_id}/projects/{project_id}"
    resp = request_with_retries(session, "DELETE", url, params={"version": API_VERSION})

    if resp.status_code in (200, 204):
        return True

    log.error("Failed to delete project %s: %s %s", project_id, resp.status_code, resp.text)
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--org-id", required=True, help="Snyk organization ID (UUID)")
    parser.add_argument(
        "--token",
        default=os.environ.get("SNYK_TOKEN"),
        help="Snyk API token (defaults to SNYK_TOKEN env var)",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SNYK_API_BASE_URL", DEFAULT_BASE_URL),
        help="Snyk API base URL (use a regional URL for EU/AU tenants)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List inactive projects that would be deleted, but don't delete them",
    )
    confirm_group = parser.add_mutually_exclusive_group()
    confirm_group.add_argument(
        "--yes",
        action="store_true",
        help="Skip all confirmation prompts (for unattended/cron use)",
    )
    confirm_group.add_argument(
        "--per-project",
        action="store_true",
        help="Prompt individually for each project instead of one bulk confirmation",
    )
    return parser.parse_args()


def prompt_per_project(name: str, project_id: str) -> str:
    """Ask what to do with one project. Returns 'y' (delete), 'n' (skip),
    'a' (delete this and all remaining without further prompts), or
    'q' (skip this and abort remaining deletions)."""
    while True:
        answer = input(f"Delete {name} ({project_id})? [y/N/a/q] ").strip().lower()
        if answer in ("y", "n", "a", "q"):
            return answer
        if answer == "":
            return "n"
        print("Please answer y (yes), n (no), a (yes to all), or q (quit).")


def main() -> int:
    args = parse_args()

    if not args.token:
        log.error("No API token provided. Set SNYK_TOKEN or pass --token.")
        return 1

    session = build_session(args.token)

    log.info("Fetching inactive projects for org %s ...", args.org_id)
    inactive_projects = list(iter_inactive_projects(session, args.base_url, args.org_id))

    if not inactive_projects:
        log.info("No inactive projects found. Nothing to do.")
        return 0

    log.info("Found %d inactive project(s):", len(inactive_projects))
    for project in inactive_projects:
        attrs = project.get("attributes", {})
        log.info("  - %s (%s)", attrs.get("name", "<unknown>"), project["id"])

    if args.dry_run:
        log.info("Dry run: no projects were deleted.")
        return 0

    if not args.yes and not args.per_project:
        answer = input(f"\nDelete these {len(inactive_projects)} project(s)? [y/N] ").strip().lower()
        if answer != "y":
            log.info("Aborted by user.")
            return 0

    deleted, skipped, failed = 0, 0, 0
    confirm_all = args.yes
    for project in inactive_projects:
        project_id = project["id"]
        name = project.get("attributes", {}).get("name", "<unknown>")

        if args.per_project and not confirm_all:
            answer = prompt_per_project(name, project_id)
            if answer == "q":
                log.info("Stopping at user request.")
                break
            if answer == "a":
                confirm_all = True
            elif answer == "n":
                skipped += 1
                continue

        if delete_project(session, args.base_url, args.org_id, project_id):
            log.info("Deleted: %s (%s)", name, project_id)
            deleted += 1
        else:
            failed += 1

    log.info("Done. Deleted %d project(s), skipped %d, %d failure(s).", deleted, skipped, failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
