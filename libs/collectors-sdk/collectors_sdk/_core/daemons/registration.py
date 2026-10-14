"""Collector registration: platform assets, collector record and its icon."""

from typing import Any

from collectors_sdk.seam.daemons import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
)
from xtm_oaev_sdk import ConfigurationProtocol

__all__ = ["CollectorRegistration"]


class CollectorRegistration:
    """Implements ``CollectorRegistrationPort``."""

    def register(
        self,
        configuration: ConfigurationProtocol,
        api: Any,
        collector_type: str,
        logger: Any,
    ) -> dict[str, Any]:
        if configuration.get("collector_period") is None:
            configuration.set("collector_period", DEFAULT_PERIOD_SECONDS)
        icon_path = configuration.get("collector_icon_filepath")
        icon_name = configuration.get("collector_id") + ".png"
        with open(icon_path, "rb") as icon_file_handle:
            collector_icon = (icon_name, icon_file_handle, "image/png")
            document = api.document.upsert(document={}, file=collector_icon)
            if configuration.get("collector_platform") is not None:
                security_platform_input = {
                    "asset_name": configuration.get("collector_name"),
                    "asset_external_reference": configuration.get("collector_id"),
                    "security_platform_type": configuration.get("collector_platform"),
                    "security_platform_logo_light": document.get("document_id"),
                    "security_platform_logo_dark": document.get("document_id"),
                }
                description = configuration.get("collector_platform_description")
                if description:
                    security_platform_input["asset_description"] = description
                tag_ids = self._upsert_platform_tags(
                    api, logger, configuration.get("collector_platform_tags")
                )
                if tag_ids:
                    security_platform_input["asset_tags"] = tag_ids
                security_platform = api.security_platform.upsert(
                    security_platform_input
                )
            else:
                security_platform = {}
            security_platform_id = security_platform.get("asset_id")
            config = {
                "collector_id": configuration.get("collector_id"),
                "collector_name": configuration.get("collector_name"),
                "collector_type": collector_type,
                "collector_period": configuration.get("collector_period"),
                "collector_security_platform": security_platform_id,
                # Optional author override; None lets the platform fall back to
                # the collector name.
                "collector_author": configuration.get("collector_author"),
            }
        with open(icon_path, "rb") as icon_file_handle:
            collector_icon = (icon_name, icon_file_handle, "image/png")
            api.collector.create(config, collector_icon)

        return config

    def _upsert_platform_tags(self, api, logger, tag_names) -> list:
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
                tag = api.tag.upsert(
                    {"tag_name": tag_name, "tag_color": DEFAULT_PLATFORM_TAG_COLOR}
                )
                tag_id = tag.get("tag_id")
                if tag_id:
                    tag_ids.append(tag_id)
            except Exception as err:  # noqa: BLE001
                logger.warning(
                    f"Could not upsert security platform tag {tag_name}: {err}"
                )
        return tag_ids
