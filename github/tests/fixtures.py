"""Fake GitHub data and a fake client for the tests."""

from github_collector.client import GitHubApiError


def repo(name, node_id, **overrides):
    values = {
        "id": abs(hash(node_id)) % 10_000_000,
        "node_id": node_id,
        "name": name,
        "full_name": f"acme/{name}",
        "owner": {"login": "acme"},
        "html_url": f"https://github.com/acme/{name}",
        "description": f"The {name} repository",
        "private": False,
        "visibility": "public",
        "default_branch": "main",
        "archived": False,
        "fork": False,
        "pushed_at": "2026-11-20T10:00:00Z",
        "language": "Python",
        "topics": ["ctem", "Security"],
    }
    values.update(overrides)
    return values


REPOSITORIES = [
    repo("api", "R_api"),
    repo("legacy", "R_legacy", archived=True, visibility="private", private=True),
    repo("forked", "R_forked", fork=True),
]

WORKFLOWS = {
    "acme/api": [
        {
            "id": 11,
            "node_id": "W_ci",
            "name": "CI",
            "path": ".github/workflows/ci.yml",
            "state": "active",
            "html_url": "https://github.com/acme/api/blob/main/.github/workflows/ci.yml",
            "updated_at": "2026-11-01T00:00:00Z",
        }
    ],
}

PACKAGES = {
    "npm": [
        {
            "id": 77,
            "name": "api-sdk",
            "package_type": "npm",
            "visibility": "public",
            "version_count": 3,
            "html_url": "https://github.com/orgs/acme/packages/npm/package/api-sdk",
            "updated_at": "2026-11-02T00:00:00Z",
            "repository": {"full_name": "acme/api", "node_id": "R_api"},
        }
    ],
}


class FakeClient:
    """Answers like GitHubClient from the data above."""

    def __init__(self, repositories=None, fail_owner=None, packages_status=None):
        self.repositories = REPOSITORIES if repositories is None else repositories
        self.fail_owner = fail_owner
        self.packages_status = packages_status
        self.calls = []

    def organization_repositories(self, org):
        self.calls.append(("org", org))
        if org == self.fail_owner:
            raise GitHubApiError("boom", 502)
        return iter(self.repositories)

    def user_repositories(self, user):
        self.calls.append(("user", user))
        if user == self.fail_owner:
            raise GitHubApiError("boom", 502)
        return iter([])

    def repository_workflows(self, full_name):
        if full_name == "acme/legacy":
            raise GitHubApiError("Actions disabled", 404)
        return iter(WORKFLOWS.get(full_name, []))

    def owner_packages(self, owner, package_type, is_org):
        if self.packages_status:
            raise GitHubApiError("no read:packages", self.packages_status)
        return iter(PACKAGES.get(package_type, []))
