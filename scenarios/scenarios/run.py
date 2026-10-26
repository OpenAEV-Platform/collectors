"""A run of the collector: read the channel's pointer, download the release it names, check
it, and hand it to the sink whole, or not at all. A release with any finding is not handed on:
the run says why, and the next run tries again. A release handed on is not handed on again.
"""

from dataclasses import dataclass
from typing import Any, Protocol

from scenarios.github import POINTER_LIMIT, GitHubSource, SourceError
from scenarios.release import (
    MANIFEST_NAME,
    ListedRelease,
    Pointer,
    check_assets,
    check_file,
    listed_release,
    pointer_from,
)
from scenarios.strict_json import read_strict_json

MANIFEST_LIMIT = 20 * 1024 * 1024


class Logger(Protocol):
    """What a run says, at the level it says it: the daemon's logger, or the standard one."""

    def info(self, message: str) -> Any: ...

    def error(self, message: str) -> Any: ...


@dataclass(frozen=True)
class VerifiedRelease:
    """A release as its channel's pointer names it: the pointer, the manifest's bytes and
    document, what it lists, and each file it lists, by name, checked against it."""

    pointer: Pointer
    manifest: bytes
    document: Any
    listed: ListedRelease
    files: dict[str, bytes]


class Sink(Protocol):
    """Where a verified release goes: the platform, once its interface is known."""

    def send(self, release: VerifiedRelease) -> None: ...


class DryRunSink:
    """A sink that only says what it would send."""

    def __init__(self, logger: Logger) -> None:
        self._logger = logger

    def send(self, release: VerifiedRelease) -> None:
        listed = release.listed
        self._logger.info(
            f"Dry run: release {release.pointer.release} verified, "
            f"{len(listed.scenarios)} scenario(s), {listed.payload_versions} payload version(s); "
            "nothing is sent to the platform"
        )
        for external_id, version in listed.scenarios:
            self._logger.info(f"Dry run: scenario {external_id} {version}")


class Collect:
    """The runs of the collector, from ``source`` to ``sink``, for ``channel`` of
    ``repository``; it keeps the pointer it last handed on."""

    def __init__(
        self,
        source: GitHubSource,
        sink: Sink,
        *,
        repository: str,
        channel: str,
        logger: Logger,
    ) -> None:
        self.sink = sink
        self._source = source
        self._repository = repository
        self._channel = channel
        self._logger = logger
        self._handled: Pointer | None = None

    def run(self) -> None:
        """One run. A failing sink raises, and the release is tried again by the next run."""
        try:
            release = self._verified()
        except (SourceError, ValueError) as error:
            self._logger.error(f"The release of {self._channel} is not used: {error}")
            return
        if release is None:
            return
        self.sink.send(release)
        self._handled = release.pointer

    def _verified(self) -> VerifiedRelease | None:
        data = self._source.pointer(self._channel)
        if data is None:
            self._logger.info(
                f"{self._repository} has no release on {self._channel} yet"
            )
            return None
        pointer = pointer_from(
            read_strict_json(data, limit=POINTER_LIMIT),
            repository=self._repository,
            channel=self._channel,
        )
        if pointer == self._handled:
            self._logger.info(
                f"Release {pointer.release} of {self._channel} already handled"
            )
            return None
        assets = self._source.assets(pointer.release)
        if MANIFEST_NAME not in assets:
            raise ValueError(f"the release {pointer.release} has no {MANIFEST_NAME}")
        manifest = self._source.download(assets[MANIFEST_NAME], limit=MANIFEST_LIMIT)
        document = read_strict_json(manifest, limit=MANIFEST_LIMIT)
        listed = listed_release(
            manifest,
            document,
            pointer,
            repository=self._repository,
            channel=self._channel,
        )
        check_assets(listed.files, {name: asset.size for name, asset in assets.items()})
        files = {}
        for expected in listed.files:
            data = self._source.download(assets[expected.name], limit=expected.limit)
            check_file(expected, data)
            files[expected.name] = data
        return VerifiedRelease(pointer, manifest, document, listed, files)
