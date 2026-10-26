"""The channel's pointer: the release a channel names, and its manifest's SHA-256."""

from typing import Any

import pytest

from scenarios.release import Pointer, pointer_from

REPOSITORY = "OpenAEV-Platform/scenarios"
SHA = "a" * 64


def _document(**changes: Any) -> dict[str, Any]:
    document = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "channel": "edge",
        "release": "2026.10.27.1",
        "manifest_sha256": SHA,
    }
    document.update(changes)
    return document


def test_a_pointer_is_read() -> None:
    assert pointer_from(_document(), repository=REPOSITORY, channel="edge") == Pointer(
        release="2026.10.27.1", manifest_sha256=SHA
    )


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "an object"),
        ({**_document(), "extra": 1}, "its five fields"),
        ({k: v for k, v in _document().items() if k != "release"}, "its five fields"),
        (_document(schema_version=2), "schema_version 1"),
        (_document(schema_version=True), "schema_version 1"),
        (_document(repository="someone/else"), "another repository"),
        (_document(channel="stable"), "another channel"),
        (_document(release="2026.10.27"), "not a release name"),
        (_document(release="2026.02.30.1"), "not a release name"),
        (_document(release="2026.10.27.0"), "not a release name"),
        (_document(release=20261027), "not a release name"),
        (_document(manifest_sha256="A" * 64), "64 lower-case hex digits"),
        (_document(manifest_sha256="a" * 63), "64 lower-case hex digits"),
    ],
)
def test_a_pointer_out_of_its_shape_is_refused(document: Any, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        pointer_from(document, repository=REPOSITORY, channel="edge")
