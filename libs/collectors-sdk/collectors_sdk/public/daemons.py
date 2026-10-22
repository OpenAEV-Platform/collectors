"""Collector daemon adapter: registers the collector, then runs its callback on
a schedule.

The adapter speaks the collector daemon seam types and delegates to the core
implementation of its ports. The API client is injected (``BaseClient``).
"""

from collectors_sdk._core.daemons import CollectorRegistration, CollectorSchedule
from collectors_sdk.seam.daemons import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
    CollectorRegistrationPort,
    CollectorSchedulePort,
)
from xtm_oaev_sdk import BaseDaemon, Configuration, PingAlive

__all__ = ["CollectorDaemon", "DEFAULT_PERIOD_SECONDS", "DEFAULT_PLATFORM_TAG_COLOR"]

_registration: CollectorRegistrationPort = CollectorRegistration()
_schedule: CollectorSchedulePort = CollectorSchedule()


class CollectorDaemon(BaseDaemon):
    """Implementation of a daemon of Collector type. Note that it requires
    specific configuration keys to run its setup.
    `collector_icon_filepath`: relative path to an icon image (preferably PNG)
    `collector_id`: unique identifier for the collector (UUIDv4)
    `collector_period`: time to wait in seconds between each loop execution; note
    that this time is added to the time the loop takes to run, so the actual total
    time between each loop start is time_of_loop+period.
    `collector_author` (optional): source-declared author override for the
    collector's payloads and contracts; when absent, the platform attributes
    them to the collector's name.
    `collector_platform_description` (optional): description applied to the
    security platform auto-created when `collector_platform` is set, so the
    read-only card is not empty in the UI.
    `collector_platform_tags` (optional): list of tag names (or a
    comma-separated string) applied to the auto-created security platform.
    """

    def __init__(
        self,
        configuration: Configuration,
        callback: callable = None,
        logger=None,
        api_client=None,
        collector_type=None,
    ):
        super().__init__(configuration, callback, logger, api_client)
        if collector_type is None:
            raise ValueError("Must define a value for collector type")
        self.collector_type = collector_type

    def _setup(self):
        config = _registration.register(
            self._configuration, self.api, self.collector_type, self.logger
        )
        PingAlive(self.api, config, self.logger, "collector").start()

    def _start_loop(self):
        _schedule.run(self._try_callback, self._configuration.get("collector_period"))
