"""The channel's pointer: the release a channel names, and its manifest's SHA-256."""

from typing import Any

import pytest

from scenarios.release import Pointer, pointer_from, release_order

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


def test_a_field_added_to_the_pointer_is_ignored() -> None:
    """A later pointer may gain fields; only a break changes its schema_version."""
    document = {**_document(), "published_at": "2026-10-29T09:00:00Z"}
    assert pointer_from(document, repository=REPOSITORY, channel="edge") == Pointer(
        release="2026.10.27.1", manifest_sha256=SHA
    )


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "an object"),
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


def test_releases_are_ordered_by_their_numbers_not_by_their_characters() -> None:
    assert release_order("2026.10.27.10") == (2026, 10, 27, 10)
    assert release_order("2026.10.27.123456789") == (2026, 10, 27, 123456789)
    ordered = ["2026.10.27.1", "2026.10.27.9", "2026.10.27.10", "2026.10.27.123456789"]
    assert sorted(reversed(ordered), key=release_order) == ordered
    assert sorted(ordered, key=str) != ordered  # as text, 10 comes before 9
    assert release_order("2026.10.28.1") > release_order("2026.10.27.123456789")


@pytest.mark.parametrize("name", ["", "latest", "2026.13.01.1", "2026.10.27.0"])
def test_a_name_that_is_not_a_release_has_no_order(name: str) -> None:
    with pytest.raises(ValueError, match="not a release name"):
        release_order(name)
