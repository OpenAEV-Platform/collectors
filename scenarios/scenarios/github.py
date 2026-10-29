"""The channel's pointer and the release's files, read from the GitHub REST API, which serves
a public and a private repository alike. Every answer is read bounded; redirects are followed
by hand, a few at most, over HTTPS only, and the token goes to the API's host alone: an asset's
download is redirected to GitHub's storage, which must never see it."""

import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from scenarios.strict_json import read_strict_json

POINTER_LIMIT = 4 * 1024
RELEASE_ANSWER_LIMIT = 4 * 1024 * 1024  # GitHub's answer listing a release's files
MAX_REDIRECTS = 5
CALL_THREAD = "scenarios-source-call"
DOWNLOAD_DEADLINE = 300  # seconds for one answer, however slowly it comes
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_RATE_LIMITED = frozenset({403, 429})
_CHUNK = 64 * 1024


def _no_auth(request: requests.PreparedRequest) -> requests.PreparedRequest:
    """The request as it is: what the session would add from a .netrc is never added."""
    return request


class SourceError(Exception):
    """The source could not be read as it should be; the message never holds the token."""


@dataclass(frozen=True)
class Asset:
    """A file of a release: its name, its size as GitHub gives it, and the API URL to get it."""

    name: str
    size: int
    url: str


class GitHubSource:
    """The releases of ``repository``, read from the GitHub API at ``api_url``."""

    def __init__(
        self,
        api_url: str,
        repository: str,
        token: str | None,
        *,
        require_https: bool = True,
        timeout: tuple[float, float] = (10, 60),
        session: requests.Session | None = None,
    ) -> None:
        self._https = require_https
        if require_https and urlsplit(api_url).scheme != "https":
            raise SourceError("the GitHub API URL must use HTTPS")
        self._api = api_url.rstrip("/")
        self._host = urlsplit(self._api).netloc
        self._repository = repository
        self._token = token
        self._timeout = timeout
        self._session = session or requests.Session()
        self._in_flight: threading.Thread | None = None
        # The repository's, not the release's: an asset's number is global, and this API serves
        # an asset of any release of the repository. What binds an asset to the release is the
        # SHA-256 the manifest lists, checked on every file downloaded.
        self._asset_url = re.compile(
            re.escape(f"{self._api}/repos/{repository}/releases/assets/") + "[0-9]+"
        )

    def pointer(self, channel: str) -> bytes | None:
        """The bytes of ``channel``'s pointer on the ``channels`` branch; none when the
        repository has no pointer for it yet."""
        url = (
            f"{self._api}/repos/{self._repository}/contents/{channel}.json?ref=channels"
        )
        # A private repository answers 404 without a token: the run says so, as "no pointer".
        return self.follow(
            url,
            limit=POINTER_LIMIT,
            accept="application/vnd.github.raw+json",
            missing_ok=True,
        )

    def assets(self, release: str) -> dict[str, Asset]:
        """The files of the release named ``release``, by name."""
        url = f"{self._api}/repos/{self._repository}/releases/tags/{release}"
        data = self.follow(
            url, limit=RELEASE_ANSWER_LIMIT, accept="application/vnd.github+json"
        )
        try:
            document = read_strict_json(data or b"", limit=RELEASE_ANSWER_LIMIT)
        except ValueError as error:
            raise SourceError(
                f"the release {release} is not as GitHub gives it: {error}"
            ) from error
        listed = document.get("assets") if isinstance(document, dict) else None
        if not isinstance(listed, list):
            raise SourceError(
                f"the release {release} is not as GitHub gives it: no assets"
            )
        assets: dict[str, Asset] = {}
        for value in listed:
            name = value.get("name") if isinstance(value, dict) else None
            size = value.get("size") if isinstance(value, dict) else None
            link = value.get("url") if isinstance(value, dict) else None
            if (
                not isinstance(name, str)
                or type(size) is not int
                or not isinstance(link, str)
            ):
                raise SourceError(
                    f"the release {release} is not as GitHub gives it: an asset"
                )
            if name in assets:
                raise SourceError(
                    f"the release {release} has an asset named twice: {name!r}"
                )
            if not self._asset_url.fullmatch(link):
                raise SourceError(
                    f"the release {release} has an asset served elsewhere: {name!r}"
                )
            assets[name] = Asset(name, size, link)
        return assets

    def download(self, asset: Asset, *, limit: int) -> bytes:
        """The bytes of ``asset``, at most ``limit``."""
        data = self.follow(asset.url, limit=limit, accept="application/octet-stream")
        if data is None:
            raise SourceError(f"{asset.name!r} cannot be downloaded: not found")
        return data

    def follow(
        self, url: str, *, limit: int, accept: str, missing_ok: bool = False
    ) -> bytes | None:
        """The body ``url`` answers, redirects followed; none for a 404 when ``missing_ok``;
        within ``DOWNLOAD_DEADLINE`` in all, headers, redirects and body alike. The call runs in
        a thread of its own, so that a server however slow cannot hold the run past it: the
        thread, left behind, ends with its connection's read timeout or the server's answer.
        Until it ends, every call is refused rather than left in flight beside it: one thread
        and one connection at most are ever left behind.
        """
        if self._in_flight is not None and self._in_flight.is_alive():
            raise SourceError(
                "a call cut at its deadline is still in flight: try again later"
            )
        outcome: dict[str, bytes | None | BaseException] = {}
        deadline = DOWNLOAD_DEADLINE

        def call() -> None:
            try:
                outcome["data"] = self._follow(url, limit, accept, missing_ok)
            except BaseException as error:  # noqa: B036 - handed to the caller as it is
                outcome["error"] = error

        worker = threading.Thread(target=call, name=CALL_THREAD, daemon=True)
        worker.start()
        worker.join(deadline)
        if worker.is_alive():
            self._in_flight = worker
            parts = urlsplit(url)
            raise SourceError(
                f"{parts.netloc}{parts.path} took over {deadline} seconds"
            )
        error = outcome.get("error")
        if isinstance(error, BaseException):
            raise error
        data = outcome.get("data")
        return data if isinstance(data, bytes) else None

    def _follow(
        self, url: str, limit: int, accept: str, missing_ok: bool
    ) -> bytes | None:
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(url)
            if self._https and parts.scheme != "https":
                raise SourceError(
                    f"{parts.netloc}{parts.path} is not served over HTTPS"
                )
            headers = {
                "Accept": accept,
                # Assets are archives and small documents: compression gains nothing, and
                # none asked for is none to decompress. What is read is bounded all the same.
                "Accept-Encoding": "identity",
                "User-Agent": "openaev-scenarios-collector",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if self._token and parts.netloc == self._host:
                headers["Authorization"] = f"Bearer {self._token}"
            where = f"{parts.netloc}{parts.path}"
            try:
                response = self._get(url, headers)
            except (requests.RequestException, OSError) as error:
                raise SourceError(
                    f"cannot read {where}: {type(error).__name__}"
                ) from error
            with response:
                if response.status_code in _REDIRECTS:
                    location = response.headers.get("Location")
                    if not location:
                        raise SourceError(f"{where} redirects nowhere")
                    url = urljoin(url, location)
                    continue
                if response.status_code == 404 and missing_ok:
                    return None
                if response.status_code in _RATE_LIMITED and (
                    response.headers.get("X-RateLimit-Remaining") == "0"
                ):
                    raise SourceError(self._rate_limited())
                if response.status_code != 200:
                    raise SourceError(f"{where} answered {response.status_code}")
                return _bounded(
                    response, limit, where, time.monotonic() + DOWNLOAD_DEADLINE
                )
        raise SourceError(f"too many redirects, over {MAX_REDIRECTS}")

    def _rate_limited(self) -> str:
        """Why the run stops when GitHub has no call left to give it: a run costs three calls
        and one more for each file, and GitHub gives 60 an hour without a token."""
        if self._token:
            return "GitHub's rate limit is reached for the token: try again later"
        return (
            "GitHub's rate limit is reached for calls without a token (60 an hour): "
            "set SCENARIOS_GITHUB_TOKEN"
        )

    def _get(self, url: str, headers: dict[str, str]) -> requests.Response:
        """The answer to a GET of ``url``, its body unread. Sent through the transport
        directly: the session would read a redirect's body whole, even with redirects left to
        the caller, to prepare the next request."""
        prepared = self._session.prepare_request(
            # No authentication but the token: a .netrc would replace it, or follow redirects.
            requests.Request("GET", url, headers=headers, auth=_no_auth)
        )
        settings = self._session.merge_environment_settings(
            prepared.url, {}, True, None, None
        )
        return self._session.get_adapter(str(prepared.url)).send(
            prepared,
            stream=True,
            timeout=self._timeout,
            verify=settings["verify"] if settings["verify"] is not None else True,
            cert=settings["cert"],
            proxies=settings["proxies"],
        )


def _bounded(
    response: requests.Response, limit: int, where: str, deadline: float
) -> bytes:
    """The body of ``response``, at most ``limit`` bytes, read before ``deadline``: each read
    returns what one receive gives, so that the deadline is checked however slowly it comes.
    The caller stops waiting at its own deadline; this one ends the thread it leaves behind.
    """
    data = bytearray()
    try:
        while chunk := response.raw.read1(_CHUNK, decode_content=True):
            data += chunk
            if len(data) > limit:
                raise SourceError(f"{where} is over {limit} bytes")
            if time.monotonic() > deadline:
                raise SourceError(f"{where} took over {DOWNLOAD_DEADLINE} seconds")
    except (requests.RequestException, urllib3.exceptions.HTTPError, OSError) as error:
        raise SourceError(f"cannot read {where}: {type(error).__name__}") from error
    return bytes(data)
