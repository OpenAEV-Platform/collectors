"""Heartbeat enrollment tests for BaseCollector platform registration."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

from collectors_sdk._core.base import BaseCollector


class TestHeartbeat:
    """Heartbeat tests for BaseCollector._register_with_platform()."""

    @staticmethod
    def _build_collector() -> BaseCollector:
        collector = BaseCollector.__new__(BaseCollector)
        collector.collector_id = "collector-123"
        collector.name = "test-collector"
        collector.logger = MagicMock()
        collector.oaev_api = MagicMock()
        collector._explicit_api = False
        collector._settings = SimpleNamespace(
            collector=SimpleNamespace(
                icon_filepath="/tmp/icon.png",
                platform="test-platform",
                period=timedelta(seconds=60),
            )
        )
        collector.oaev_api.document.upsert.return_value = {"document_id": "doc-1"}
        collector.oaev_api.security_platform.upsert.return_value = {"asset_id": "sp-1"}
        return collector

    def test_register_with_platform_enrolls_pingalive_with_expected_config(self) -> None:
        collector = self._build_collector()

        with patch("builtins.open", mock_open(read_data=b"icon")), patch(
            "pyoaev.utils.PingAlive"
        ) as pingalive_cls:
            pingalive_thread = MagicMock()
            pingalive_cls.return_value = pingalive_thread

            collector._register_with_platform()

            expected_config = {
                "collector_id": collector.collector_id,
                "collector_name": collector.name,
                "collector_type": collector._settings.collector.platform,
                "collector_period": 60,
                "collector_security_platform": "sp-1",
            }
            pingalive_cls.assert_called_once_with(
                collector.oaev_api,
                expected_config,
                collector.logger,
                "collector",
            )

    def test_register_with_platform_calls_pingalive_thread_start(self) -> None:
        collector = self._build_collector()

        with patch("builtins.open", mock_open(read_data=b"icon")), patch(
            "pyoaev.utils.PingAlive"
        ) as pingalive_cls:
            pingalive_thread = MagicMock()
            pingalive_cls.return_value = pingalive_thread

            collector._register_with_platform()

            pingalive_thread.start.assert_called_once_with()

    def test_register_with_platform_passes_collector_api_and_logger_to_pingalive(
        self,
    ) -> None:
        collector = self._build_collector()

        with patch("builtins.open", mock_open(read_data=b"icon")), patch(
            "pyoaev.utils.PingAlive"
        ) as pingalive_cls:
            collector._register_with_platform()

            pingalive_cls.assert_called_once()
            args, _ = pingalive_cls.call_args
            assert args[0] is collector.oaev_api
            assert args[2] is collector.logger

    def test_register_with_platform_skips_pingalive_when_api_is_explicit(self) -> None:
        collector = self._build_collector()
        collector._explicit_api = True

        with patch("pyoaev.utils.PingAlive") as pingalive_cls:
            collector._register_with_platform()

            pingalive_cls.assert_not_called()
            collector.oaev_api.document.upsert.assert_not_called()
            collector.oaev_api.security_platform.upsert.assert_not_called()
            collector.oaev_api.collector.create.assert_not_called()
