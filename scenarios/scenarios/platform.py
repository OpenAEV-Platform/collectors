"""The platform's catalogue, where a verified release goes: one multipart call to its sync, with
the manifest and every file the release lists, the archives and the payload version files, each
under its own name. The platform checks them again before it uses anything.

The sync is synchronous: the platform processes the release, then answers 200 with what it
added and what it refused. Nothing else is taken for its answer. The body is streamed from the
files already held, never copied, with its length known: the platform is not sent a chunked body.

The token goes to the platform's URL alone: no redirect is followed, and no .netrc replaces it.
The answer is read bounded, within a deadline, and must be about the release sent. A call that
fails raises, and the next run sends the release again; the platform keeps the last release it
applied, so a release sent twice changes nothing.
"""

import secrets
import time
from collections.abc import Iterator, Sequence
from typing import Any, Protocol
from urllib.parse import urlsplit

import requests
import urllib3
from urllib3.fields import RequestField

from scenarios.run import VerifiedRelease
from scenarios.strict_json import read_strict_json

ANSWER_LIMIT = 1024 * 1024
CONNECT_TIMEOUT = 10  # seconds to connect
# Seconds the platform may take, once it has the release, before its answer begins: the read
# timeout of the sync, which processes the release in the call. A release sent again because the
# platform was still at work would be sent every period, and may well have been applied.
SYNC_READ_TIMEOUT = 30 * 60
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


Parts = Sequence[tuple[str, tuple[str, bytes, str]]]


def release_parts(release: VerifiedRelease) -> Parts:
    """The parts of the call for ``release``: its manifest, then each file it lists."""
    parts: list[tuple[str, tuple[str, bytes, str]]] = [
        ("manifest", ("manifest.json", release.manifest, "application/json"))
    ]
    for listed in release.listed.files:
        data = release.files[listed.name]
        parts.append(("archives", (listed.name, data, _content_type(listed.name))))
    return parts


class MultipartBody:
    """A ``multipart/form-data`` body of ``parts`` (name, then file name, bytes and content type),
    byte for byte what ``requests`` makes of ``files=``, as a file to read from. Its length is
    known, so that it is sent with a Content-Length; the files are read where they are, a piece
    at a time, never copied into a buffer of the whole body."""

    def __init__(self, parts: Parts, *, boundary: str | None = None) -> None:
        self._boundary = boundary or secrets.token_hex(16)
        self._pieces: list[bytes | memoryview] = []
        for name, (filename, data, kind) in parts:
            field = RequestField(name=name, data=data, filename=filename)
            field.make_multipart(content_type=kind)
            head = f"--{self._boundary}\r\n{field.render_headers()}"
            self._pieces += [head.encode(), memoryview(data), b"\r\n"]
        self._pieces.append(f"--{self._boundary}--\r\n".encode())
        self._length = sum(len(piece) for piece in self._pieces)
        self._piece, self._offset = 0, 0

    @property
    def content_type(self) -> str:
        return f"multipart/form-data; boundary={self._boundary}"

    def __len__(self) -> int:
        return self._length

    def read(self, size: int = -1) -> bytes:
        """The next ``size`` bytes of the body, or what is left of it; none at its end."""
        wanted = self._length if size < 0 else size
        chunks: list[bytes] = []
        while wanted > 0 and self._piece < len(self._pieces):
            piece = self._pieces[self._piece]
            taken = piece[self._offset : self._offset + wanted]
            chunks.append(bytes(taken))
            wanted -= len(taken)
            self._offset += len(taken)
            if self._offset >= len(piece):
                self._piece, self._offset = self._piece + 1, 0
        return b"".join(chunks)

    def __iter__(self) -> Iterator[bytes]:
        """What ``requests`` looks for to send a body it does not hold whole."""
        while chunk := self.read(_CHUNK):
            yield chunk


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
        answer = self._post(MultipartBody(release_parts(release)))
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

    def _post(self, body: MultipartBody) -> dict[str, Any]:
        try:
            response = self._session.post(
                self._url,
                data=body,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": body.content_type,
                },
                auth=_no_auth,
                allow_redirects=False,
                timeout=(CONNECT_TIMEOUT, SYNC_READ_TIMEOUT),
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
            answer = bytearray()
            deadline = time.monotonic() + DEADLINE
            try:
                # What one receive gives, so that the deadline is checked however slowly it comes.
                while chunk := response.raw.read1(_CHUNK, decode_content=True):
                    answer += chunk
                    if len(answer) > ANSWER_LIMIT:
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
        return _answer(bytes(answer))


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
