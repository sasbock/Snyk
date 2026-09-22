"""An in-memory stand-in for SnykClient used by discovery/resolver unit tests.

Matches SnykClient's method surface exactly so resolvers/discovery.py
can't tell the difference -- no unit test in this suite makes a network
call (see requirements doc §8.4).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def project(project_id: str, name: str, project_type: str) -> Dict[str, Any]:
    """Builds a project resource shaped like the real REST API's."""
    return {"type": "project", "id": project_id, "attributes": {"name": name, "type": project_type}}


class FakeSnykClient:
    def __init__(
        self,
        orgs: Optional[List[str]] = None,
        group_orgs: Optional[Dict[str, Optional[List[str]]]] = None,
        org_projects: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        org_targets: Optional[Dict[str, List[str]]] = None,
        project_targets: Optional[Dict[Tuple[str, str], str]] = None,
        project_tags: Optional[Dict[Tuple[str, str], List[Tuple[str, str]]]] = None,
        org_assets: Optional[Dict[str, List[str]]] = None,
        asset_projects: Optional[Dict[Tuple[str, str], List[str]]] = None,
    ) -> None:
        self.orgs = orgs or []
        self.group_orgs = group_orgs or {}
        self.org_projects = org_projects or {}
        self.org_targets = org_targets or {}
        # (org_id, project_id) -> target_id, so list_org_projects(target_id=...) can filter
        self.project_targets = project_targets or {}
        # (org_id, project_id) -> [(key, value), ...]
        self.project_tags = project_tags or {}
        self.org_assets = org_assets or {}
        # (org_id, asset_id) -> [project_id, ...]
        self.asset_projects = asset_projects or {}

    def list_orgs(self) -> List[Dict[str, Any]]:
        return [{"id": org_id} for org_id in self.orgs]

    def list_group_orgs(self, group_id: str) -> Optional[List[Dict[str, Any]]]:
        orgs = self.group_orgs.get(group_id)
        if orgs is None:
            return None
        return [{"id": org_id} for org_id in orgs]

    def list_org_projects(
        self,
        org_id: str,
        target_id: Optional[str] = None,
        tag: Optional[Tuple[str, str]] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        if org_id not in self.org_projects:
            return None
        projects = self.org_projects[org_id]
        if target_id is not None:
            projects = [
                p for p in projects if self.project_targets.get((org_id, p["id"])) == target_id
            ]
        if tag is not None:
            projects = [
                p for p in projects if tag in self.project_tags.get((org_id, p["id"]), [])
            ]
        return projects

    def get_project(self, org_id: str, project_id: str) -> Optional[Dict[str, Any]]:
        for p in self.org_projects.get(org_id, []):
            if p["id"] == project_id:
                return p
        return None

    def list_org_targets(self, org_id: str) -> Optional[List[Dict[str, Any]]]:
        if org_id not in self.org_targets:
            return None
        return [{"id": t} for t in self.org_targets[org_id]]

    def get_target(self, org_id: str, target_id: str) -> Optional[Dict[str, Any]]:
        if target_id in self.org_targets.get(org_id, []):
            return {"id": target_id}
        return None

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        if asset_id in self.org_assets.get(org_id, []):
            return {"id": asset_id}
        return None

    def list_asset_projects(self, org_id: str, asset_id: str) -> Optional[List[Dict[str, Any]]]:
        project_ids = self.asset_projects.get((org_id, asset_id))
        if project_ids is None:
            return None
        return [{"id": pid} for pid in project_ids]
