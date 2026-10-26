"""The manifest the pointer names, the files it lists, and the release's assets."""

import hashlib
from typing import Any

import pytest

from scenarios.release import (
    ARCHIVE_LIMIT,
    PAYLOAD_FILE_LIMIT,
    ListedFile,
    Pointer,
    check_assets,
    check_file,
    listed_release,
)

REPOSITORY = "OpenAEV-Platform/scenarios"
ARCHIVE = "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d-1.0.0.zip"
PAYLOAD = "process-discovery-ps-1.0.0.json"


def _manifest(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "channel": "edge",
        "release": "2026.10.27.1",
        "release_approver": "laugiov",
        "items": [
            {
                "external_id": "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d",
                "version": "1.0.0",
                "archive": {"name": ARCHIVE, "size": 10, "sha256": "a" * 64},
            }
        ],
        "payloads": [
            {
                "payload": "process-discovery-ps",
                "version": "1.0.0",
                "file": {"name": PAYLOAD, "size": 3, "sha256": "b" * 64},
            }
        ],
    }
    document.update(changes)
    return document


def _listed(document: Any, data: bytes = b"manifest") -> Any:
    pointer = Pointer("2026.10.27.1", hashlib.sha256(data).hexdigest())
    return listed_release(
        data, document, pointer, repository=REPOSITORY, channel="edge"
    )


def test_the_manifest_lists_its_scenarios_and_its_files() -> None:
    listed = _listed(_manifest())

    assert listed.scenarios == (("0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d", "1.0.0"),)
    assert listed.payload_versions == 1
    assert listed.files == (
        ListedFile(ARCHIVE, 10, "a" * 64, ARCHIVE_LIMIT),
        ListedFile(PAYLOAD, 3, "b" * 64, PAYLOAD_FILE_LIMIT),
    )


def test_a_manifest_the_pointer_does_not_name_is_refused() -> None:
    pointer = Pointer("2026.10.27.1", "0" * 64)
    with pytest.raises(ValueError, match="not the one the pointer names"):
        listed_release(
            b"manifest", _manifest(), pointer, repository=REPOSITORY, channel="edge"
        )


def _without(field: str) -> dict[str, Any]:
    document = _manifest()
    del document[field]
    return document


def _item(**archive: Any) -> list[dict[str, Any]]:
    item = _manifest()["items"][0]
    return [{**item, "archive": {**item["archive"], **archive}}]


def _payload(**file: Any) -> list[dict[str, Any]]:
    entry = _manifest()["payloads"][0]
    return [{**entry, "file": {**entry["file"], **file}}]


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "an object"),
        (_manifest(repository="someone/else"), "another repository"),
        (_manifest(channel="stable"), "another channel"),
        (_manifest(release="2026.10.27.2"), "another release"),
        (_without("release_approver"), "never approved"),
        (_manifest(release_approver="Laugiov"), "never approved"),
        (_manifest(items="x"), "items"),
        (_manifest(items=[]), "no scenario"),
        (_manifest(payloads={}), "payloads"),
        (_manifest(items=[{"external_id": "x", "version": "1.0.0"}]), "archive"),
        (
            _manifest(items=[{**_manifest()["items"][0], "external_id": 1}]),
            "external_id",
        ),
        (_manifest(items=_item(name="../x.zip")), "plain file name"),
        (_manifest(items=_item(name="a/b.zip")), "plain file name"),
        (_manifest(items=_item(name="manifest.json")), "plain file name"),
        (_manifest(items=_item(name="")), "plain file name"),
        (_manifest(items=_item(size=-1)), "size"),
        (_manifest(items=_item(size=True)), "size"),
        (_manifest(items=_item(size=ARCHIVE_LIMIT + 1)), "over"),
        (_manifest(items=_item(sha256="A" * 64)), "sha256"),
        (_manifest(payloads=_payload(size=PAYLOAD_FILE_LIMIT + 1)), "over"),
        (_manifest(payloads=[{"payload": "x", "version": "1.0.0"}]), "file"),
        (_manifest(payloads=_payload(name=ARCHIVE)), "listed twice"),
    ],
)
def test_a_manifest_out_of_what_the_collector_uses_is_refused(
    document: Any, why: str
) -> None:
    with pytest.raises(ValueError, match=why):
        _listed(document)


def test_every_listed_file_is_an_asset_of_its_size_and_nothing_else_stands_beside() -> (
    None
):
    listed = _listed(_manifest()).files

    check_assets(listed, {"manifest.json": 8, ARCHIVE: 10, PAYLOAD: 3})


@pytest.mark.parametrize(
    ("assets", "why"),
    [
        ({"manifest.json": 8, ARCHIVE: 10}, f"{PAYLOAD} is not an asset"),
        (
            {"manifest.json": 8, ARCHIVE: 11, PAYLOAD: 3},
            f"{ARCHIVE} is 11 bytes, not 10",
        ),
        ({"manifest.json": 8, ARCHIVE: 10, PAYLOAD: 3, "extra.zip": 1}, "extra.zip"),
    ],
)
def test_assets_that_differ_from_the_manifest_refuse_the_release(
    assets: dict[str, int], why: str
) -> None:
    with pytest.raises(ValueError, match=why):
        check_assets(_listed(_manifest()).files, assets)


def test_a_downloaded_file_has_the_listed_size_and_sha256() -> None:
    data = b"abc"
    listed = ListedFile(
        PAYLOAD, 3, hashlib.sha256(data).hexdigest(), PAYLOAD_FILE_LIMIT
    )

    check_file(listed, data)
    with pytest.raises(ValueError, match="4 bytes, not 3"):
        check_file(listed, b"abcd")
    with pytest.raises(ValueError, match="another SHA-256"):
        check_file(listed, b"abd")
