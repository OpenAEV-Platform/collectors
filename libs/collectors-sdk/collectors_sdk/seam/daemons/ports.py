"""Collector daemon ports: the behaviour the public daemon expects from the core."""

from typing import Any, Callable, Protocol, runtime_checkable

from xtm_oaev_sdk import ConfigurationProtocol

__all__ = ["CollectorRegistrationPort", "CollectorSchedulePort"]


@runtime_checkable
class CollectorRegistrationPort(Protocol):
    """Registers a collector and its security platform on the platform."""

    def register(
        self,
        configuration: ConfigurationProtocol,
        api: Any,
        collector_type: str,
        logger: Any,
    ) -> dict[str, Any]:
        """Default the period, upload the icon, upsert the security platform
        (description, tags) and create the collector; its config is returned."""


@runtime_checkable
class CollectorSchedulePort(Protocol):
    """Runs a collector callback periodically."""

    def run(self, callback: Callable[[], Any], delay: Any) -> None:
        """Run ``callback`` now, then every ``delay`` seconds, forever."""
