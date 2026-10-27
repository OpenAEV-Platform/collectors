"""The platform sink: a verified release goes to the platform's catalogue in one call, the
manifest and every file it lists; what the platform refuses is said; a call that fails raises,
so that the next run sends the release again."""

import hashlib
import logging
import tracemalloc
from pathlib import Path

import pytest
import requests
from tests.fake_platform import FakePlatform, fake_platform

from scenarios.platform import (
    CONNECT_TIMEOUT,
    SYNC_READ_TIMEOUT,
    MultipartBody,
    PlatformError,
    PlatformSink,
    release_parts,
)
from scenarios.release import ListedFile, ListedRelease, Pointer
from scenarios.run import VerifiedRelease

TOKEN = "platform-token"
TENANT = "2b0f1c4e-6a7d-4e8f-9a1b-3c5d7e9f0a2b"
ARCHIVE, PAYLOAD = "s-1.0.0.zip", "p-1.0.0.json"
FILES = {ARCHIVE: b"an import archive", PAYLOAD: b'{"payload": 1}'}
MANIFEST = b'{"release": "2026.10.27.1"}'


def _release() -> VerifiedRelease:
    listed = ListedRelease(
        (("s", "1.0.0"),),
        1,
        tuple(
            ListedFile(name, len(data), hashlib.sha256(data).hexdigest(), len(data))
            for name, data in FILES.items()
        ),
    )
    pointer = Pointer("2026.10.27.1", hashlib.sha256(MANIFEST).hexdigest())
    return VerifiedRelease(pointer, MANIFEST, {}, listed, dict(FILES))


def _sink(fake: FakePlatform, tenant: str | None = None) -> PlatformSink:
    return PlatformSink(fake.url, TOKEN, tenant, logging.getLogger("t"))


def _applied(**changes: object) -> dict[str, object]:
    return {
        "release": "2026.10.27.1",
        "applied": True,
        "added": 1,
        "unchanged": 0,
        "refused": [],
        **changes,
    }


def test_the_manifest_and_every_file_go_in_one_call_with_the_token() -> None:
    with fake_platform() as fake:
        fake.answer(_applied())
        _sink(fake).send(_release())

    (call,) = fake.calls
    assert call.path == "/api/catalog/sync"
    assert call.authorization == f"Bearer {TOKEN}"
    assert [(part.name, part.filename) for part in call.parts] == [
        ("manifest", "manifest.json"),
        ("archives", ARCHIVE),
        ("archives", PAYLOAD),
    ]
    assert [part.data for part in call.parts] == [MANIFEST, *FILES.values()]


def test_a_tenant_s_catalogue_is_synced_under_its_path() -> None:
    with fake_platform() as fake:
        fake.answer(_applied())
        _sink(fake, TENANT).send(_release())

    assert fake.calls[0].path == f"/api/tenants/{TENANT}/catalog/sync"


def test_what_the_platform_refuses_is_said_and_the_release_counts_as_sent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    refusal = {
        "external_id": "s",
        "version": "1.0.0",
        "reason": "Archive hash mismatch",
    }
    with fake_platform() as fake:
        fake.answer(_applied(added=0, refused=[refusal]))
        with caplog.at_level(logging.INFO):
            _sink(fake).send(_release())

    assert "s 1.0.0 refused by the platform: Archive hash mismatch" in caplog.text
    assert any(record.levelno == logging.ERROR for record in caplog.records)


def test_a_release_the_platform_already_has_is_said_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with fake_platform() as fake:
        fake.answer(_applied(applied=False, added=0))
        with caplog.at_level(logging.INFO):
            _sink(fake).send(_release())

    assert "already holds release 2026.10.27.1" in caplog.text


@pytest.mark.parametrize("status", [400, 401, 403, 404, 500])
def test_a_call_the_platform_refuses_raises_without_the_token(status: int) -> None:
    with fake_platform() as fake:
        fake.answer({"message": f"refused with {TOKEN}"}, status=status)
        with pytest.raises(PlatformError) as error:
            _sink(fake).send(_release())

    assert str(status) in str(error.value)
    assert TOKEN not in str(error.value)


def test_a_redirect_is_never_followed() -> None:
    with fake_platform() as fake:
        fake.status, fake.headers = 307, {"Location": "http://elsewhere.invalid/"}
        with pytest.raises(PlatformError, match="307"):
            _sink(fake).send(_release())

    assert len(fake.calls) == 1


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b'{"applied": "yes"}'],
    ids=["not-json", "a-list", "wrong-types"],
)
def test_an_answer_out_of_its_shape_raises(body: bytes) -> None:
    with fake_platform() as fake:
        fake.status, fake.body = 200, body
        fake.headers = {"Content-Type": "application/json"}
        with pytest.raises(PlatformError):
            _sink(fake).send(_release())


def test_a_netrc_never_replaces_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    netrc = tmp_path / ".netrc"
    netrc.write_text("machine 127.0.0.1 login someone password other\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    with fake_platform() as fake:
        fake.answer(_applied())
        _sink(fake).send(_release())

    assert fake.calls[0].authorization == f"Bearer {TOKEN}"


def test_an_answer_over_its_limit_stops_being_read() -> None:
    with fake_platform() as fake:
        fake.status, fake.body = 200, b"{" + b" " * 2_000_000 + b"}"
        fake.headers = {"Content-Type": "application/json"}
        with pytest.raises(PlatformError, match="answer is over 1048576 bytes"):
            _sink(fake).send(_release())


def test_an_answer_for_another_release_raises() -> None:
    with fake_platform() as fake:
        fake.answer(_applied(release="2026.10.20.1"))
        with pytest.raises(PlatformError, match="2026.10.20.1"):
            _sink(fake).send(_release())


def test_an_answer_that_trickles_stops_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scenarios.platform.DEADLINE", 1.0)
    with fake_platform() as fake:
        fake.answer(_applied())
        fake.trickle = 0.2  # seconds between two bytes
        with pytest.raises(PlatformError, match="took over"):
            _sink(fake).send(_release())


def test_a_platform_reached_over_http_is_said_to_be(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO):
        PlatformSink("http://openaev:8080", TOKEN, None, logging.getLogger("t"))
        PlatformSink("https://openaev.example.org", TOKEN, None, logging.getLogger("t"))

    assert caplog.text.count("over HTTP") == 1


def _requests_made(
    parts: list[tuple[str, tuple[str, bytes, str]]],
) -> tuple[bytes, str]:
    """The body ``requests`` makes of ``files=parts``, and the boundary it chose."""
    prepared = requests.Request(
        "POST", "http://platform.invalid", files=parts
    ).prepare()
    assert isinstance(prepared.body, bytes)
    return prepared.body, prepared.headers["Content-Type"].split("boundary=")[1]


def test_the_body_is_what_requests_makes_of_the_files() -> None:
    parts = release_parts(_release())
    expected, boundary = _requests_made(parts)

    body = MultipartBody(parts, boundary=boundary)

    assert len(body) == len(expected)
    assert body.content_type == f"multipart/form-data; boundary={boundary}"
    assert body.read() == expected


def test_the_body_is_read_in_pieces_of_any_size_and_ends() -> None:
    parts = release_parts(_release())
    expected, boundary = _requests_made(parts)
    body = MultipartBody(parts, boundary=boundary)

    pieces = []
    while piece := body.read(7):
        assert len(piece) <= 7
        pieces.append(piece)

    assert b"".join(pieces) == expected
    assert body.read(7) == b""


def test_a_file_name_is_written_as_requests_writes_it() -> None:
    parts = [("archives", ('a "quoted" nam\u00e9.zip', b"x", "application/zip"))]
    expected, boundary = _requests_made(parts)

    assert MultipartBody(parts, boundary=boundary).read() == expected


def test_the_body_does_not_copy_the_files() -> None:
    size = 32 * 1024 * 1024
    parts = [("archives", ("big.zip", bytes(size), "application/zip"))]
    tracemalloc.start()
    try:
        body = MultipartBody(parts)
        while body.read(64 * 1024):
            pass
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 1024 * 1024  # a few pieces, never the file


def test_the_call_is_the_multipart_requests_makes_and_has_its_length() -> None:
    expected, old_boundary = _requests_made(release_parts(_release()))
    with fake_platform() as fake:
        fake.answer(_applied())
        _sink(fake).send(_release())

    (call,) = fake.calls
    boundary = call.content_type.split("boundary=")[1]
    assert call.content_type.startswith("multipart/form-data; boundary=")
    assert call.body.replace(boundary.encode(), old_boundary.encode()) == expected
    assert call.content_length == str(len(call.body))
    assert call.transfer_encoding is None


def test_the_answer_is_waited_for_as_long_as_the_sync_read_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The platform processes the release before it answers: the read timeout is the time it
    may take, not the 5 minutes between two bytes of a download."""
    with fake_platform() as fake:
        fake.answer(_applied())
        fake.delay = 1.0
        monkeypatch.setattr("scenarios.platform.SYNC_READ_TIMEOUT", 0.3)
        with pytest.raises(PlatformError, match="ReadTimeout"):
            _sink(fake).send(_release())
        monkeypatch.setattr("scenarios.platform.SYNC_READ_TIMEOUT", 5)
        _sink(fake).send(_release())


def test_the_sync_has_its_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[object] = []

    class Adapter:
        def send(self, request: object, **options: object) -> object:
            asked.append(options.get("timeout"))
            raise requests.ConnectTimeout("too slow")

    session = requests.Session()
    monkeypatch.setattr(session, "get_adapter", lambda url: Adapter())
    sink = PlatformSink(
        "https://platform.example", TOKEN, None, logging.getLogger("t"), session=session
    )
    with pytest.raises(PlatformError, match="ConnectTimeout"):
        sink.send(_release())

    assert asked == [(CONNECT_TIMEOUT, SYNC_READ_TIMEOUT)]
    assert SYNC_READ_TIMEOUT >= 15 * 60


@pytest.mark.parametrize("status", [201, 202, 204])
def test_a_status_other_than_the_sync_s_200_raises(status: int) -> None:
    """The sync answers 200 once the release is applied; nothing else is taken for it."""
    with fake_platform() as fake:
        fake.answer(_applied(), status=status)
        with pytest.raises(PlatformError, match=str(status)):
            _sink(fake).send(_release())
