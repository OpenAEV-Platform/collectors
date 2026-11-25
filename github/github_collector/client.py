"""Minimal read-only client for the GitHub REST API.

Works against github.com (``https://api.github.com``) and GitHub Enterprise Server
(``https://<host>/api/v3``). Only ``GET`` requests are issued: the collector never changes
anything on GitHub.

Rate limits are respected in three ways:

- conditional requests: the ``ETag`` of every page is kept in memory between runs and sent
  back as ``If-None-Match``; a ``304 Not Modified`` answer reuses the cached body and does
  not count against the primary rate limit;
- a primary rate limit exhausted (``X-RateLimit-Remaining: 0``) waits for
  ``X-RateLimit-Reset``, bounded by ``max_rate_limit_wait_seconds``;
- a secondary rate limit or a transient error (``Retry-After``, 429, 5xx) is retried with an
  exponential backoff.
"""

import logging
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlencode

import requests

GITHUB_COM_API_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
DEFAULT_TIMEOUT_SECONDS = 30
PER_PAGE = 100


class GitHubApiError(Exception):
    """A GitHub API call failed (after retries, or with a non retryable status)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        """Keep the message and the HTTP status, when there was one."""
        super().__init__(message)
        self.status_code = status_code


def next_page_url(link_header: str | None) -> str | None:
    """Return the ``rel="next"`` URL of a ``Link`` header, or None on the last page."""
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        url = section[0].strip()
        if any(param.strip() == 'rel="next"' for param in section[1:]):
            return url.strip("<>")
    return None


class GitHubClient:
    """Read-only GitHub REST client with conditional requests and rate-limit backoff."""

    def __init__(
        self,
        token: str,
        api_url: str = GITHUB_COM_API_URL,
        logger: logging.Logger | Any | None = None,
        session: requests.Session | None = None,
        max_retries: int = 4,
        backoff_seconds: float = 2.0,
        max_rate_limit_wait_seconds: int = 900,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Open a session carrying the token and the API version headers."""
        self.api_url = api_url.rstrip("/")
        self.logger = logger or logging.getLogger(__name__)
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "openaev-github-collector",
            }
        )
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.max_rate_limit_wait_seconds = max_rate_limit_wait_seconds
        self._sleep = sleep
        self._clock = clock
        # url -> (etag, parsed body, next page url)
        self._cache: dict[str, tuple[str, Any, str | None]] = {}

    # -- low level -----------------------------------------------------------------------

    def _url(self, path: str, params: dict[str, Any] | None = None) -> str:
        url = path if path.startswith("http") else f"{self.api_url}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    def _rate_limit_wait(self, response: requests.Response) -> float | None:
        """Return the seconds to wait before retrying a rate-limited answer, or None."""
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                return self.backoff_seconds
        if response.headers.get("X-RateLimit-Remaining") == "0":
            reset = response.headers.get("X-RateLimit-Reset")
            if reset and reset.isdigit():
                return max(float(reset) - self._clock(), 0.0) + 1.0
            return self.backoff_seconds
        return None

    def _retry_wait(self, response: requests.Response, attempt: int) -> float | None:
        """Return the seconds to wait before retrying an error answer, or None to fail."""
        if response.status_code in (403, 429):
            wait: float | None = self._rate_limit_wait(response)
            return wait
        if response.status_code in RETRYABLE_STATUSES:
            return self.backoff_seconds * float(2**attempt)
        return None

    def _store(self, url: str, response: requests.Response) -> tuple[Any, str | None]:
        """Parse a 200 answer and keep it with its ETag for the next conditional request."""
        body = response.json()
        next_url = next_page_url(response.headers.get("Link"))
        etag = response.headers.get("ETag")
        if etag:
            self._cache[url] = (etag, body, next_url)
        return body, next_url

    def _send(self, url: str, attempt: int) -> requests.Response | None:
        """Send a conditional GET; None after a network error that may be retried."""
        cached = self._cache.get(url)
        headers = {"If-None-Match": cached[0]} if cached else {}
        try:
            return self.session.get(
                url, headers=headers, timeout=DEFAULT_TIMEOUT_SECONDS
            )
        except requests.RequestException as err:
            if attempt >= self.max_retries:
                raise GitHubApiError(f"GET {url} failed: {err}") from err
            self._sleep(self.backoff_seconds * float(2**attempt))
            return None

    def _get_page(self, url: str) -> tuple[Any, str | None]:
        """GET one page; return its parsed body and the next page URL."""
        response = None
        for attempt in range(self.max_retries + 1):
            response = self._send(url, attempt)
            if response is None:
                continue
            cached = self._cache.get(url)
            if response.status_code == 304 and cached:
                return cached[1], cached[2]
            if response.status_code == 200:
                return self._store(url, response)
            wait = self._retry_wait(response, attempt)
            if wait is None or attempt >= self.max_retries:
                break
            if wait > self.max_rate_limit_wait_seconds:
                raise GitHubApiError(
                    f"GET {url}: rate limited for {int(wait)} s, more than the "
                    f"{self.max_rate_limit_wait_seconds} s allowed",
                    response.status_code,
                )
            self.logger.warning(
                f"GitHub answered {response.status_code} on {url}, retrying in "
                f"{int(wait)} s"
            )
            self._sleep(wait)
        if response is None:
            raise GitHubApiError(f"GET {url} failed")
        raise GitHubApiError(
            f"GET {url} answered {response.status_code}: {response.text[:300]}",
            response.status_code,
        )

    # -- generic readers -----------------------------------------------------------------

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET one resource."""
        body, _ = self._get_page(self._url(path, params))
        return body

    def paginate(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        items_key: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Iterate over every item of a paginated list (``Link`` header pagination)."""
        query = dict(params or {})
        query.setdefault("per_page", PER_PAGE)
        url: str | None = self._url(path, query)
        while url:
            body, url = self._get_page(url)
            items = body.get(items_key, []) if items_key else body
            yield from items or []

    # -- GitHub resources ----------------------------------------------------------------

    def organization_repositories(self, org: str) -> Iterator[dict[str, Any]]:
        """List every repository of an organization the token can read."""
        return self.paginate(f"/orgs/{org}/repos", {"type": "all"})

    def user_repositories(self, user: str) -> Iterator[dict[str, Any]]:
        """List the repositories a user owns (private ones for the token's own user)."""
        return self.paginate(f"/users/{user}/repos", {"type": "owner"})

    def repository_workflows(self, full_name: str) -> Iterator[dict[str, Any]]:
        """List the GitHub Actions workflows of a repository."""
        return self.paginate(
            f"/repos/{full_name}/actions/workflows", items_key="workflows"
        )

    def directory_entries(
        self, full_name: str, path: str, ref: str | None = None
    ) -> list[dict[str, Any]]:
        """List the entries of one directory of a repository (one contents read)."""
        params = {"ref": ref} if ref else None
        body = self.get(f"/repos/{full_name}/contents/{path}", params)
        return body if isinstance(body, list) else []

    def owner_packages(
        self, owner: str, package_type: str, is_org: bool
    ) -> Iterator[dict[str, Any]]:
        """List the GitHub Packages of one type published by an organization or a user."""
        scope = "orgs" if is_org else "users"
        return self.paginate(
            f"/{scope}/{owner}/packages", {"package_type": package_type}
        )
