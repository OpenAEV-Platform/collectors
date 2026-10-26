"""What the collector checks of a release before handing it on: the channel's pointer, the
manifest it names, and every file the manifest lists. Pure: what is read is given."""

import datetime
import hashlib
import re
from dataclasses import dataclass
from typing import Any

POINTER_FIELDS = frozenset(
    {"schema_version", "repository", "channel", "release", "manifest_sha256"}
)
_RELEASE = re.compile(r"([0-9]{4})\.([0-9]{2})\.([0-9]{2})\.([1-9][0-9]{0,8})")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Pointer:
    """The release a channel names, and the SHA-256 of its manifest."""

    release: str
    manifest_sha256: str


def is_release_name(value: object) -> bool:
    """Whether ``value`` names a release: ``YYYY.MM.DD.N``, a day the calendar has, N from 1."""
    if not isinstance(value, str):
        return False
    found = _RELEASE.fullmatch(value)
    if found is None:
        return False
    try:
        datetime.date(int(found[1]), int(found[2]), int(found[3]))
    except ValueError:
        return False
    return True


def pointer_from(document: Any, *, repository: str, channel: str) -> Pointer:
    """The pointer ``document`` holds, for ``channel`` of ``repository``; ``ValueError`` with
    why when it is not shaped as the repository writes it, or is another's."""
    if not isinstance(document, dict):
        raise ValueError("the pointer must be an object")
    if set(document) != POINTER_FIELDS:
        raise ValueError("the pointer must hold its five fields, and nothing else")
    version = document["schema_version"]
    if type(version) is not int or version != 1:
        raise ValueError("the pointer must have schema_version 1")
    if document["repository"] != repository:
        raise ValueError(f"the pointer names another repository than {repository}")
    if document["channel"] != channel:
        raise ValueError(f"the pointer names another channel than {channel}")
    release = document["release"]
    if not is_release_name(release):
        raise ValueError(f"the pointer's release, {release!r}, is not a release name")
    sha256 = document["manifest_sha256"]
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise ValueError(
            "the pointer's manifest_sha256 must be 64 lower-case hex digits"
        )
    return Pointer(release, sha256)


# The bounds the scenarios repository builds a release within: an import archive, and the file
# of a payload version.
ARCHIVE_LIMIT = 20 * 1024 * 1024
PAYLOAD_FILE_LIMIT = 256 * 1024
# What one release may weigh in all, held in memory until it is handed on whole.
RELEASE_LIMIT = 512 * 1024 * 1024
MANIFEST_NAME = "manifest.json"
_LOGIN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SEMVER = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")


@dataclass(frozen=True)
class ListedFile:
    """A file the manifest lists: its name, size and SHA-256, and the most it may weigh."""

    name: str
    size: int
    sha256: str
    limit: int


@dataclass(frozen=True)
class ListedRelease:
    """What the manifest lists: each scenario's external ID and version, how many payload
    versions, and every file, archives first."""

    scenarios: tuple[tuple[str, str], ...]
    payload_versions: int
    files: tuple[ListedFile, ...]


def _listed_file(facts: Any, limit: int, where: str) -> ListedFile:
    if not isinstance(facts, dict):
        raise ValueError(f"{where} needs its name, size and sha256")
    name, size, sha256 = facts.get("name"), facts.get("size"), facts.get("sha256")
    if (
        not isinstance(name, str)
        or not _FILE_NAME.fullmatch(name)
        or name == MANIFEST_NAME
    ):
        raise ValueError(f"{where} must name a plain file name, not {name!r}")
    if type(size) is not int or size < 0:
        raise ValueError(f"{where} needs a size in bytes")
    if size > limit:
        raise ValueError(f"{name} is over {limit} bytes")
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise ValueError(f"{where} needs a sha256 of 64 lower-case hex digits")
    return ListedFile(name, size, sha256, limit)


def check_manifest_hash(manifest: bytes, pointer: Pointer) -> None:
    """Refuse ``manifest`` unless it is the one ``pointer`` names, before it is read at all."""
    if hashlib.sha256(manifest).hexdigest() != pointer.manifest_sha256:
        raise ValueError(
            "the manifest is not the one the pointer names: another SHA-256"
        )


def listed_release(
    manifest: bytes, document: Any, pointer: Pointer, *, repository: str, channel: str
) -> ListedRelease:
    """What the manifest ``document``, read from ``manifest``, lists, once it is the one
    ``pointer`` names, of ``repository`` and ``channel``, and approved; ``ValueError`` with why
    otherwise. Only what the collector uses is checked: the platform checks the rest."""
    if hashlib.sha256(manifest).hexdigest() != pointer.manifest_sha256:
        raise ValueError(
            "the manifest is not the one the pointer names: another SHA-256"
        )
    if not isinstance(document, dict):
        raise ValueError("the manifest must be an object")
    if document.get("repository") != repository:
        raise ValueError(f"the manifest is of another repository than {repository}")
    if document.get("channel") != channel:
        raise ValueError(f"the manifest is of another channel than {channel}")
    if document.get("release") != pointer.release:
        raise ValueError(f"the manifest is of another release than {pointer.release}")
    approver = document.get("release_approver")
    if (
        not isinstance(approver, str)
        or len(approver) > 39
        or not _LOGIN.fullmatch(approver)
    ):
        raise ValueError(
            "the manifest names no release approver: it was never approved"
        )
    items, payloads = document.get("items"), document.get("payloads")
    if not isinstance(items, list):
        raise ValueError("the manifest's items must be a list")
    if not items:
        raise ValueError("the manifest lists no scenario")
    if not isinstance(payloads, list):
        raise ValueError("the manifest's payloads must be a list")
    scenarios: list[tuple[str, str]] = []
    files: list[ListedFile] = []
    for index, item in enumerate(items):
        where = f"items[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{where} must be an object")
        external_id, version = item.get("external_id"), item.get("version")
        if not isinstance(external_id, str) or not _UUID.fullmatch(external_id):
            raise ValueError(f"{where} needs an external_id, a UUID in lower case")
        if not isinstance(version, str) or not _SEMVER.fullmatch(version):
            raise ValueError(f"{where} needs a version, MAJOR.MINOR.PATCH")
        if any(external_id == known for known, _ in scenarios):
            raise ValueError(f"the manifest lists the scenario {external_id} twice")
        scenarios.append((external_id, version))
        archive = _listed_file(item.get("archive"), ARCHIVE_LIMIT, f"{where}.archive")
        if archive.name != f"{external_id}-{version}.zip":
            raise ValueError(
                f"{where}.archive is named after another scenario or version"
            )
        files.append(archive)
    for index, entry in enumerate(payloads):
        where = f"payloads[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{where} must be an object")
        files.append(
            _listed_file(entry.get("file"), PAYLOAD_FILE_LIMIT, f"{where}.file")
        )
    names = [listed.name for listed in files]
    twice = sorted({name for name in names if names.count(name) > 1})
    if twice:
        raise ValueError(f"the manifest has a file listed twice: {', '.join(twice)}")
    if sum(listed.size for listed in files) > RELEASE_LIMIT:
        raise ValueError(f"the release is over {RELEASE_LIMIT} bytes in all")
    return ListedRelease(tuple(scenarios), len(payloads), tuple(files))


def check_assets(files: tuple[ListedFile, ...], assets: dict[str, int]) -> None:
    """Refuse the release unless every listed file is one of its ``assets``, by name, with the
    listed size, and no asset stands beside them but the manifest: it would be published.
    """
    for listed in files:
        if listed.name not in assets:
            raise ValueError(f"{listed.name} is not an asset of the release")
        if assets[listed.name] != listed.size:
            raise ValueError(
                f"{listed.name} is {assets[listed.name]} bytes, not {listed.size}"
            )
    unlisted = sorted(set(assets) - {listed.name for listed in files} - {MANIFEST_NAME})
    if unlisted:
        raise ValueError(
            f"the release has assets the manifest does not list: {', '.join(map(repr, unlisted))}"
        )


def check_file(listed: ListedFile, data: bytes) -> None:
    """Refuse ``data``, the file downloaded for ``listed``, unless it has its size and SHA-256."""
    if len(data) != listed.size:
        raise ValueError(f"{listed.name} is {len(data)} bytes, not {listed.size}")
    if hashlib.sha256(data).hexdigest() != listed.sha256:
        raise ValueError(f"{listed.name} has another SHA-256 than the manifest lists")
