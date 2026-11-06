"""Tests for the CollectorDaemon (API client injected)."""

import unittest
from unittest.mock import MagicMock, mock_open, patch

from collectors_sdk import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
    CollectorDaemon,
)
from xtm_oaev_sdk import Configuration


def _given_api(tag_ids=()) -> MagicMock:
    api = MagicMock()
    api.collector.create.return_value = {}
    api.document.upsert.return_value = {"document_id": "doc id"}
    api.security_platform.upsert.return_value = {"asset_id": "sp id"}
    api.tag.upsert.side_effect = [{"tag_id": tag_id} for tag_id in tag_ids]
    return api


def _given_collector(config_hints: dict, api: MagicMock) -> CollectorDaemon:
    return CollectorDaemon(
        configuration=Configuration(config_hints=config_hints),
        api_client=api,
        logger=MagicMock(),
        collector_type="test",
    )


@patch("builtins.open", new_callable=mock_open, read_data="data")
@patch("xtm_oaev_sdk.PingAlive.start")
class TestCollectorDaemon(unittest.TestCase):
    def test_collector_type_is_required(self, *_):
        with self.assertRaises(ValueError):
            CollectorDaemon(
                configuration=Configuration(config_hints={}),
                api_client=MagicMock(),
                logger=MagicMock(),
            )

    def test_when_no_period_config_provided_set_default_period(self, *_):
        api = _given_api()
        collector = _given_collector({"collector_id": {"data": "fake id"}}, api)

        collector._setup()

        self.assertEqual(
            collector._configuration.get("collector_period"), DEFAULT_PERIOD_SECONDS
        )

    def test_setup_registers_the_collector_and_starts_the_heartbeat(
        self, mock_ping_start, _
    ):
        api = _given_api()
        collector = _given_collector(
            {
                "collector_id": {"data": "fake id"},
                "collector_name": {"data": "Fake EDR"},
                "collector_period": {"data": 30},
            },
            api,
        )

        collector._setup()

        config = api.collector.create.call_args.args[0]
        self.assertEqual(config["collector_id"], "fake id")
        self.assertEqual(config["collector_type"], "test")
        self.assertEqual(config["collector_period"], 30)
        self.assertIsNone(config["collector_security_platform"])
        api.security_platform.upsert.assert_not_called()
        mock_ping_start.assert_called_once()

    def test_security_platform_upsert_carries_description_and_tags(self, *_):
        api = _given_api(tag_ids=("tag-1", "tag-2"))
        collector = _given_collector(
            {
                "collector_id": {"data": "fake id"},
                "collector_name": {"data": "Fake EDR"},
                "collector_platform": {"data": "EDR"},
                "collector_platform_description": {"data": "A fake EDR platform."},
                # Padded name: list values must be stripped like string ones.
                "collector_platform_tags": {"data": ["edr", " fake-vendor "]},
            },
            api,
        )

        collector._setup()

        payload = api.security_platform.upsert.call_args.args[0]
        self.assertEqual(payload["asset_description"], "A fake EDR platform.")
        self.assertEqual(payload["asset_tags"], ["tag-1", "tag-2"])
        tag_inputs = [call.args[0] for call in api.tag.upsert.call_args_list]
        self.assertEqual([t["tag_name"] for t in tag_inputs], ["edr", "fake-vendor"])
        self.assertEqual(tag_inputs[0]["tag_color"], DEFAULT_PLATFORM_TAG_COLOR)
        self.assertEqual(
            api.collector.create.call_args.args[0]["collector_security_platform"],
            "sp id",
        )

    def test_security_platform_tags_accept_comma_separated_string(self, *_):
        api = _given_api(tag_ids=("tag-1", "tag-2"))
        collector = _given_collector(
            {
                "collector_id": {"data": "fake id"},
                "collector_name": {"data": "Fake SIEM"},
                "collector_platform": {"data": "SIEM"},
                "collector_platform_tags": {"data": "siem, fake-vendor"},
            },
            api,
        )

        collector._setup()

        payload = api.security_platform.upsert.call_args.args[0]
        self.assertNotIn("asset_description", payload)
        self.assertEqual(payload["asset_tags"], ["tag-1", "tag-2"])

    def test_security_platform_tag_failure_is_logged_and_skipped(self, *_):
        api = _given_api()
        api.tag.upsert.side_effect = [Exception("boom"), {"tag_id": "tag-2"}]
        collector = _given_collector(
            {
                "collector_id": {"data": "fake id"},
                "collector_name": {"data": "Fake SIEM"},
                "collector_platform": {"data": "SIEM"},
                "collector_platform_tags": {"data": "siem,fake-vendor"},
            },
            api,
        )

        collector._setup()

        payload = api.security_platform.upsert.call_args.args[0]
        self.assertEqual(payload["asset_tags"], ["tag-2"])
        collector.logger.warning.assert_called_once()

    def test_security_platform_upsert_without_description_and_tags_is_unchanged(
        self, *_
    ):
        api = _given_api()
        collector = _given_collector(
            {
                "collector_id": {"data": "fake id"},
                "collector_name": {"data": "Fake XDR"},
                "collector_platform": {"data": "XDR"},
            },
            api,
        )

        collector._setup()

        payload = api.security_platform.upsert.call_args.args[0]
        self.assertNotIn("asset_description", payload)
        self.assertNotIn("asset_tags", payload)
        api.tag.upsert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
