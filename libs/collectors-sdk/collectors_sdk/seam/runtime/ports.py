"""Collector runtime ports: the behaviour the public runtime expects from the core."""

from typing import Any, Callable, Protocol, runtime_checkable

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

    def api_client(
        self,
        configuration: Any,
        options: CollectorDevOptions,
        models_for_source: Callable[..., list[Any]],
    ) -> Any:
        """A stand-in of the platform client serving the ``--expectations`` list as
        the pending feed and writing every update and trace to the dev sink. Exits
        with code 2 when the list is not the platform's pending expectations."""

    def run(
        self,
        callback: Callable[[], Any],
        period: Any,
        api: Any,
        options: CollectorDevOptions,
    ) -> None:
        """Run the collector's cycle once (``--once``) or on its period, then write the
        calls. Exits with code 2 without ``--expectations``."""
