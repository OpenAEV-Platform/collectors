"""Collector daemon: registers the collector, then runs its callback on a schedule."""

import sched
import time

from xtm_oaev_sdk import BaseDaemon, Configuration, PingAlive

__all__ = ["CollectorDaemon", "DEFAULT_PERIOD_SECONDS", "DEFAULT_PLATFORM_TAG_COLOR"]

DEFAULT_PERIOD_SECONDS = 60

# Neutral grey used for tags auto-created alongside the security platform,
# consistent with the tag colors already used across collectors.
DEFAULT_PLATFORM_TAG_COLOR = "#6b7280"


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
        if self._configuration.get("collector_period") is None:
            self._configuration.set("collector_period", DEFAULT_PERIOD_SECONDS)
        icon_path = self._configuration.get("collector_icon_filepath")
        icon_name = self._configuration.get("collector_id") + ".png"
        with open(icon_path, "rb") as icon_file_handle:
            collector_icon = (icon_name, icon_file_handle, "image/png")
            document = self.api.document.upsert(document={}, file=collector_icon)
            if self._configuration.get("collector_platform") is not None:
                security_platform_input = {
                    "asset_name": self._configuration.get("collector_name"),
                    "asset_external_reference": self._configuration.get("collector_id"),
                    "security_platform_type": self._configuration.get(
                        "collector_platform"
                    ),
                    "security_platform_logo_light": document.get("document_id"),
                    "security_platform_logo_dark": document.get("document_id"),
                }
                description = self._configuration.get("collector_platform_description")
                if description:
                    security_platform_input["asset_description"] = description
                tag_ids = self.__upsert_platform_tags(
                    self._configuration.get("collector_platform_tags")
                )
                if tag_ids:
                    security_platform_input["asset_tags"] = tag_ids
                security_platform = self.api.security_platform.upsert(
                    security_platform_input
                )
            else:
                security_platform = {}
            security_platform_id = security_platform.get("asset_id")
            config = {
                "collector_id": self._configuration.get("collector_id"),
                "collector_name": self._configuration.get("collector_name"),
                "collector_type": self.collector_type,
                "collector_period": self._configuration.get("collector_period"),
                "collector_security_platform": security_platform_id,
                # Optional author override; None lets the platform fall back to
                # the collector name.
                "collector_author": self._configuration.get("collector_author"),
            }
        with open(icon_path, "rb") as icon_file_handle:
            collector_icon = (icon_name, icon_file_handle, "image/png")
            self.api.collector.create(config, collector_icon)

        PingAlive(self.api, config, self.logger, "collector").start()

    def __upsert_platform_tags(self, tag_names) -> list:
        """Upserts the configured security platform tags and returns their ids.

        Accepts either a list of tag names or a comma-separated string; tag
        upsert failures are logged and skipped so the collector setup never
        fails because of a tag.
        """
        if not tag_names:
            return []
        if isinstance(tag_names, str):
            tag_names = tag_names.split(",")
        tag_ids = []
        for raw_name in tag_names:
            # Strip whitespace for both string and list inputs (YAML list values
            # can carry stray spaces too).
            tag_name = raw_name.strip() if isinstance(raw_name, str) else raw_name
            if not tag_name:
                continue
            try:
                tag = self.api.tag.upsert(
                    {"tag_name": tag_name, "tag_color": DEFAULT_PLATFORM_TAG_COLOR}
                )
                tag_id = tag.get("tag_id")
                if tag_id:
                    tag_ids.append(tag_id)
            except Exception as err:  # noqa: BLE001
                self.logger.warning(
                    f"Could not upsert security platform tag {tag_name}: {err}"
                )
        return tag_ids

    def _start_loop(self):
        scheduler = sched.scheduler(time.time, time.sleep)
        delay = self._configuration.get("collector_period")
        self._try_callback()
        scheduler.enter(
            delay=delay,
            priority=1,
            action=self.__schedule,
            argument=(scheduler, self._try_callback, delay),
        )
        scheduler.run()

    def __schedule(self, scheduler, callback, delay):
        callback()
        scheduler.enter(
            delay=delay,
            priority=1,
            action=self.__schedule,
            argument=(scheduler, callback, delay),
        )
