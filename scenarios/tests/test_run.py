"""A run: the pointer, the manifest it names and every file it lists, checked, then handed to
the sink all at once, or not at all."""

import hashlib
import json
import logging
from typing import Any

import pytest
from tests.fake_github import FakeGitHub, fake_github

from scenarios.github import GitHubSource
from scenarios.run import Collect, DryRunSink, VerifiedRelease

REPOSITORY = "OpenAEV-Platform/scenarios"
RELEASE = "2026.10.27.1"
ARCHIVE = "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d-1.0.0.zip"
PAYLOAD = "process-discovery-ps-1.0.0.json"
ARCHIVE_BYTES = b"an import archive"
PAYLOAD_BYTES = b'{"payload": 1}'


class Sink:
    def __init__(self) -> None:
        self.received: list[VerifiedRelease] = []

    def send(self, release: VerifiedRelease) -> None:
        self.received.append(release)


def _manifest(release: str = RELEASE) -> bytes:
    document = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "channel": "edge",
        "release": release,
        "release_approver": "laugiov",
        "items": [
            {
                "external_id": "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d",
                "version": "1.0.0",
                "archive": {
                    "name": ARCHIVE,
                    "size": len(ARCHIVE_BYTES),
                    "sha256": hashlib.sha256(ARCHIVE_BYTES).hexdigest(),
                },
            }
        ],
        "payloads": [
            {
                "payload": "process-discovery-ps",
                "version": "1.0.0",
                "file": {
                    "name": PAYLOAD,
                    "size": len(PAYLOAD_BYTES),
                    "sha256": hashlib.sha256(PAYLOAD_BYTES).hexdigest(),
                },
            }
        ],
    }
    return json.dumps(document).encode()


def _publish(
    fake: FakeGitHub,
    files: dict[str, bytes],
    pointer: Any = None,
    release: str = RELEASE,
) -> None:
    manifest = files["manifest.json"]
    pointer = pointer or {
        "schema_version": 1,
        "repository": REPOSITORY,
        "channel": "edge",
        "release": release,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
    }
    fake.json(f"/repos/{REPOSITORY}/contents/edge.json?ref=channels", pointer)
    assets = []
    base = len(fake.answers) * 10  # each release's assets their own numbers
    for number, (name, data) in enumerate(sorted(files.items()), start=base + 1):
        path = f"/repos/{REPOSITORY}/releases/assets/{number}"
        fake.raw(path, data)
        assets.append(
            {
                "name": name,
                "size": len(data),
                "url": f"http://127.0.0.1:{fake.port}{path}",
            }
        )
    fake.json(f"/repos/{REPOSITORY}/releases/tags/{release}", {"assets": assets})


def _collect(fake: FakeGitHub, sink: Any) -> Collect:
    source = GitHubSource(
        f"http://127.0.0.1:{fake.port}", REPOSITORY, None, require_https=False
    )
    return Collect(
        source,
        sink,
        repository=REPOSITORY,
        channel="edge",
        logger=logging.getLogger("t"),
    )


def _files(**changes: bytes) -> dict[str, bytes]:
    return {
        "manifest.json": _manifest(),
        ARCHIVE: ARCHIVE_BYTES,
        PAYLOAD: PAYLOAD_BYTES,
        **changes,
    }


def test_a_release_reaches_the_sink_whole_and_once() -> None:
    with fake_github() as fake:
        _publish(fake, _files())
        sink = Sink()
        collect = _collect(fake, sink)

        collect.run()
        collect.run()

        assert len(sink.received) == 1
        release = sink.received[0]
        assert release.pointer.release == RELEASE
        assert release.manifest == _manifest()
        assert release.files == {ARCHIVE: ARCHIVE_BYTES, PAYLOAD: PAYLOAD_BYTES}
        assert release.listed.scenarios == (
            ("0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d", "1.0.0"),
        )


def test_no_pointer_yet_sends_nothing() -> None:
    with fake_github() as fake:
        sink = Sink()
        _collect(fake, sink).run()
        assert sink.received == []


@pytest.mark.parametrize(
    "files",
    [
        _files(**{ARCHIVE: b"another archive!!"}),  # same size, another SHA-256
        _files(**{"extra.txt": b"x"}),
        {"manifest.json": _manifest(), ARCHIVE: ARCHIVE_BYTES},
    ],
)
def test_a_release_with_any_finding_sends_nothing_and_is_tried_again(
    files: dict[str, bytes],
) -> None:
    with fake_github() as fake:
        _publish(fake, files)
        sink = Sink()
        collect = _collect(fake, sink)

        collect.run()
        assert sink.received == []

        _publish(fake, _files())  # the release fixed, under the same pointer
        collect.run()
        assert len(sink.received) == 1


def test_a_manifest_not_strict_json_sends_nothing() -> None:
    with fake_github() as fake:
        _publish(fake, _files(**{"manifest.json": b'{"a": 1, "a": 2}'}))
        sink = Sink()
        _collect(fake, sink).run()
        assert sink.received == []


def test_a_pointer_out_of_its_shape_sends_nothing() -> None:
    with fake_github() as fake:
        _publish(fake, _files(), pointer={"schema_version": 1})
        sink = Sink()
        _collect(fake, sink).run()
        assert sink.received == []


def test_a_sink_that_fails_leaves_the_release_to_try_again() -> None:
    class Failing(Sink):
        def send(self, release: VerifiedRelease) -> None:
            raise RuntimeError("the platform is away")

    with fake_github() as fake:
        _publish(fake, _files())
        failing = Failing()
        collect = _collect(fake, failing)
        with pytest.raises(RuntimeError):
            collect.run()
        sink = Sink()
        collect.sink = sink
        collect.run()
        assert len(sink.received) == 1


def test_the_dry_run_sink_says_what_it_would_send(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with fake_github() as fake:
        _publish(fake, _files())
        with caplog.at_level(logging.INFO):
            _collect(fake, DryRunSink(logging.getLogger("t"))).run()

    said = caplog.text
    assert f"release {RELEASE}" in said
    assert "1 scenario(s), 1 payload version(s)" in said
    assert "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d 1.0.0" in said


def test_a_release_without_its_manifest_sends_nothing() -> None:
    with fake_github() as fake:
        _publish(fake, _files())
        assets_path = f"/repos/{REPOSITORY}/releases/tags/{RELEASE}"
        listed = json.loads(fake.answers[assets_path].body)
        listed["assets"] = [a for a in listed["assets"] if a["name"] != "manifest.json"]
        fake.json(assets_path, listed)
        sink = Sink()
        _collect(fake, sink).run()
        assert sink.received == []


def test_a_file_longer_than_listed_is_refused_as_it_is_read() -> None:
    with fake_github() as fake:
        _publish(fake, _files())
        assets_path = f"/repos/{REPOSITORY}/releases/tags/{RELEASE}"
        for asset in json.loads(fake.answers[assets_path].body)["assets"]:
            if asset["name"] == ARCHIVE:
                fake.raw(asset["url"].split(str(fake.port), 1)[1], ARCHIVE_BYTES + b"!")
        sink = Sink()
        _collect(fake, sink).run()
        assert sink.received == []


def test_the_manifest_s_hash_is_checked_before_it_is_read(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with fake_github() as fake:
        _publish(fake, _files())
        manifest_path = None
        for asset in json.loads(
            fake.answers[f"/repos/{REPOSITORY}/releases/tags/{RELEASE}"].body
        )["assets"]:
            if asset["name"] == "manifest.json":
                manifest_path = asset["url"].split(str(fake.port), 1)[1]
        fake.raw(manifest_path, b'{"a": 1, "a": 2}' + b" " * (len(_manifest()) - 16))
        with caplog.at_level(logging.ERROR):
            _collect(fake, Sink()).run()
    assert "another SHA-256" in caplog.text
    assert "a key twice" not in caplog.text


def test_a_file_is_read_no_further_than_its_listed_size(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with fake_github() as fake:
        _publish(fake, _files())
        for asset in json.loads(
            fake.answers[f"/repos/{REPOSITORY}/releases/tags/{RELEASE}"].body
        )["assets"]:
            if asset["name"] == ARCHIVE:
                fake.raw(asset["url"].split(str(fake.port), 1)[1], b"x" * 100_000)
        with caplog.at_level(logging.ERROR):
            _collect(fake, Sink()).run()
    assert f"is over {len(ARCHIVE_BYTES)} bytes" in caplog.text


def test_a_release_handled_once_is_never_handed_on_again() -> None:
    """Even when its channel came back to it: A, then B, then A again."""
    pointer_path = f"/repos/{REPOSITORY}/contents/edge.json?ref=channels"
    later = "2026.10.28.1"
    with fake_github() as fake:
        sink = Sink()
        collect = _collect(fake, sink)
        _publish(fake, _files())
        collect.run()
        first = fake.answers[pointer_path]
        _publish(fake, _files(**{"manifest.json": _manifest(later)}), release=later)
        collect.run()
        fake.answers[pointer_path] = first
        collect.run()

        assert [release.pointer.release for release in sink.received] == [
            RELEASE,
            later,
        ]
