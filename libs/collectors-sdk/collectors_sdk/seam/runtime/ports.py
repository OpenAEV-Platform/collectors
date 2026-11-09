"""Collector runtime ports: the behaviour the public runtime expects from the core."""

from typing import Protocol, runtime_checkable

from collectors_sdk.seam.runtime.models import CollectorDevOptions

__all__ = ["CollectorDevRuntimePort"]


@runtime_checkable
class CollectorDevRuntimePort(Protocol):
    """Runs a collector without the platform (dev mode)."""

    def options(self, argv: list[str] | None = None) -> CollectorDevOptions:
        """The collector's dev options, read from ``argv`` (the process arguments when
        ``None``). Options are read only under their full name; injector options and
        the collector's own flags are left alone."""

    def help(self) -> str:
        """Help of the collector's dev options: the common ones and its own."""

    def exit_on_help(self, options: CollectorDevOptions) -> None:
        """Print the dev help and exit with code 0 when ``options`` ask for it."""
