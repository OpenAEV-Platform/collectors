"""Collector runtime adapters: the dev options and dev help of a collector.

Each adapter speaks the runtime seam types and delegates to the core implementation of
its port.
"""

from collectors_sdk._core.runtime import CollectorDevRuntime
from collectors_sdk.seam.runtime import CollectorDevOptions, CollectorDevRuntimePort

__all__ = ["CollectorDevOptions", "collector_dev_help", "collector_dev_options"]

_dev: CollectorDevRuntimePort = CollectorDevRuntime()


def collector_dev_options(argv: list[str] | None = None) -> CollectorDevOptions:
    """Reads the dev options of a collector: the common ones plus its own.

    :param argv: the arguments to read, the process arguments when omitted.
    :return: the options, frozen. Options are read only under their full name;
        injector options and the collector's own flags are left alone.
    """
    return _dev.options(argv)


def collector_dev_help() -> str:
    """Returns the help of the collector dev options."""
    return _dev.help()
