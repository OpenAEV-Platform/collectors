"""The platform's catalogue, where a verified release goes: one multipart call to its sync, with
the manifest and every file the release lists, the archives and the payload version files, each
under its own name. The platform checks them again before it uses anything.

The token goes to the platform's URL alone: no redirect is followed, and no .netrc replaces it.
The answer is read bounded, within a deadline, and must be about the release sent. A call that
fails raises, and the next run sends the release again; the platform keeps the last release it
applied, so a release sent twice changes nothing.
"""

import time
from typing import Any, Protocol
from urllib.parse import urlsplit

import requests
import urllib3

from scenarios.run import VerifiedRelease
from scenarios.strict_json import read_strict_json

ANSWER_LIMIT = 1024 * 1024
TIMEOUT = (10, 300)  # seconds to connect, then between two reads of the answer
DEADLINE = 600  # seconds for the whole answer, however slowly it comes
_CHUNK = 64 * 1024
_TYPES = {".zip": "application/zip", ".json": "application/json"}


class Logger(Protocol):
    def info(self, message: str) -> Any: ...

    def warning(self, message: str) -> Any: ...

    def error(self, message: str) -> Any: ...


class PlatformError(Exception):
    """The platform did not take the release; the message never holds the token."""


def _no_auth(request: requests.PreparedRequest) -> requests.PreparedRequest:
    """The request as it is: what the session would add from a .netrc is never added."""
    return request


def _content_type(name: str) -> str:
    return next(
        (kind for suffix, kind in _TYPES.items() if name.endswith(suffix)),
        "application/octet-stream",
    )


class PlatformSink:
    """Sends each verified release to the catalogue of the platform at ``url``, of the tenant
    ``tenant_id`` when one is given."""

    def __init__(
        self,
        url: str,
        token: str,
        tenant_id: str | None,
        logger: Logger,
        *,
        session: requests.Session | None = None,
    ) -> None:
        scope = f"/api/tenants/{tenant_id}" if tenant_id else "/api"
        self._url = f"{url.rstrip('/')}{scope}/catalog/sync"
        self._token = token
        self._logger = logger
        self._session = session or requests.Session()
        if urlsplit(url).scheme != "https":
            logger.warning(
                "The platform is reached over HTTP: the token and the release go in clear"
            )

    def send(self, release: VerifiedRelease) -> None:
        parts: list[tuple[str, tuple[str, bytes, str]]] = [
            ("manifest", ("manifest.json", release.manifest, "application/json"))
        ]
        for listed in release.listed.files:
            data = release.files[listed.name]
            parts.append(("archives", (listed.name, data, _content_type(listed.name))))
        answer = self._post(parts)
        name = answer["release"]
        if name != release.pointer.release:
            raise PlatformError(
                f"the platform answered for release {name}, not {release.pointer.release}"
            )
        if not answer["applied"]:
            self._logger.info(f"The platform already holds release {name}")
            return
        self._logger.info(
            f"Release {name} synced: {answer['added']} added, "
            f"{answer['unchanged']} unchanged, {len(answer['refused'])} refused"
        )
        for refusal in answer["refused"]:
            self._logger.error(
                f"{refusal['external_id']} {refusal['version']} refused by the platform: "
                f"{refusal['reason']}"
            )

    def _post(self, parts: list[tuple[str, tuple[str, bytes, str]]]) -> dict[str, Any]:
        try:
            response = self._session.post(
                self._url,
                files=parts,
                headers={"Authorization": f"Bearer {self._token}"},
                auth=_no_auth,
                allow_redirects=False,
                timeout=TIMEOUT,
                stream=True,
            )
        except requests.RequestException as error:
            raise PlatformError(
                f"cannot reach the platform: {type(error).__name__}"
            ) from error
        with response:
            if response.status_code != 200:
                raise PlatformError(
                    f"the platform answered {response.status_code} to the sync"
                )
            body = bytearray()
            deadline = time.monotonic() + DEADLINE
            try:
                # What one receive gives, so that the deadline is checked however slowly it comes.
                while chunk := response.raw.read1(_CHUNK, decode_content=True):
                    body += chunk
                    if len(body) > ANSWER_LIMIT:
                        raise PlatformError(
                            f"the platform's answer is over {ANSWER_LIMIT} bytes"
                        )
                    if time.monotonic() > deadline:
                        raise PlatformError(
                            f"the platform's answer took over {DEADLINE} seconds"
                        )
            except (
                requests.RequestException,
                urllib3.exceptions.HTTPError,
                OSError,
            ) as error:
                raise PlatformError(
                    f"cannot read the platform's answer: {type(error).__name__}"
                ) from error
        return _answer(bytes(body))


def _answer(body: bytes) -> dict[str, Any]:
    """The platform's answer, refused unless it is shaped as its sync gives it."""
    try:
        document = read_strict_json(body, limit=ANSWER_LIMIT)
    except ValueError as error:
        raise PlatformError(f"the platform's answer is not JSON: {error}") from error
    refused = document.get("refused") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("release"), str)
        or not isinstance(document.get("applied"), bool)
        or type(document.get("added")) is not int
        or type(document.get("unchanged")) is not int
        or not isinstance(refused, list)
        or not all(
            isinstance(item, dict)
            and all(
                isinstance(item.get(key), str)
                for key in ("external_id", "version", "reason")
            )
            for item in refused
        )
    ):
        raise PlatformError("the platform's answer is not shaped as its sync gives it")
    return document
