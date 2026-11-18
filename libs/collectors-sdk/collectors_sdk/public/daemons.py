"""Collector daemon adapter: registers the collector, then runs its callback on
a schedule.

The adapter speaks the collector daemon seam types and delegates to the core
implementation of its ports. The API client is injected (``BaseClient``).
"""

from collectors_sdk._core.daemons import CollectorRegistration, CollectorSchedule
from collectors_sdk._core.runtime import CollectorDevRuntime
from collectors_sdk.public.expectations import expectations_models_for_source
from collectors_sdk.seam.daemons import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
    CollectorRegistrationPort,
    CollectorSchedulePort,
)
from collectors_sdk.seam.runtime import CollectorDevRuntimePort
from xtm_oaev_sdk import BaseDaemon, Configuration, PingAlive

__all__ = ["CollectorDaemon", "DEFAULT_PERIOD_SECONDS", "DEFAULT_PLATFORM_TAG_COLOR"]

_registration: CollectorRegistrationPort = CollectorRegistration()
_schedule: CollectorSchedulePort = CollectorSchedule()
_dev: CollectorDevRuntimePort = CollectorDevRuntime()


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

    Started with ``--dev``, the collector runs without the platform: it never builds the
    API client, serves the ``--expectations`` list (the platform's pending expectations,
    ``xtm_oaev_sdk.InjectExpectationOutput``, as an injector's ``--emit expectations``
    writes it) as its pending feed, starts no heartbeat, and writes the updates and
    traces it would send to the dev sink, one JSON list (``--out``, or stdout).
    ``--once`` runs one cycle. With ``--help`` (or ``-h``), it prints its dev options
    and exits with code 0, before building the API client or reaching the platform.
    """

    def __init__(
        self,
        configuration: Configuration,
        callback: callable = None,
        logger=None,
        api_client=None,
        collector_type=None,
    ):
        self._dev_options = _dev.options()
        _dev.exit_on_help(self._dev_options)
        if self._dev_options.enabled:
            api_client = _dev.api_client(
                configuration, self._dev_options, expectations_models_for_source
            )
        super().__init__(configuration, callback, logger, api_client)
        if collector_type is None:
            raise ValueError("Must define a value for collector type")
        self.collector_type = collector_type

    def _setup(self):
        config = _registration.register(
            self._configuration, self.api, self.collector_type, self.logger
        )
        if not self._dev_options.enabled:
            PingAlive(self.api, config, self.logger, "collector").start()

    def _start_loop(self):
        if self._dev_options.enabled:
            _dev.run(
                self._try_callback,
                self._configuration.get("collector_period"),
                self.api,
                self._dev_options,
            )
            return
        _schedule.run(self._try_callback, self._configuration.get("collector_period"))
