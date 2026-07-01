"""RED tests for BaseCollector heartbeat enrollment."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from collectors_sdk import BaseCollector


class TestHeartbeat:
    """Heartbeat setup tests for BaseCollector.start()."""

    @staticmethod
    def _build_collector() -> BaseCollector:
        collector = BaseCollector.__new__(BaseCollector)
        collector.collector_id = "collector-123"
        collector.name = "test-collector"
        collector.oaev_api = object()
        collector.logger = MagicMock()
        collector._settings = SimpleNamespace(
            collector=SimpleNamespace(platform="test-platform")
        )
        collector._get_period_seconds = MagicMock(return_value=60)
        collector._setup = MagicMock()
        collector._run_cycle = MagicMock()
        collector._schedule = MagicMock()
        collector.source = SimpleNamespace(signatures=[SimpleNamespace(value="telemetry")])
        return collector

    @staticmethod
    def _patch_start_runtime() -> tuple[MagicMock, MagicMock]:
        scheduler = MagicMock()
        scheduler.enter = MagicMock()
        scheduler.run = MagicMock()
        parse_args = patch(
            "argparse.ArgumentParser.parse_args",
            return_value=SimpleNamespace(dump_config_schema=False),
        )
        scheduler_patch = patch("sched.scheduler", return_value=scheduler)
        return parse_args, scheduler_patch

    def test_start_enrolls_pingalive_with_expected_config(self) -> None:
        collector = self._build_collector()
        parse_args, scheduler_patch = self._patch_start_runtime()

        with parse_args, scheduler_patch, patch(
            "collectors_sdk._core.base_collector.collector.PingAlive",
            create=True,
        ) as pingalive_cls:
            pingalive_thread = MagicMock()
            pingalive_cls.return_value = pingalive_thread

            collector.start()

            expected_config = {
                "collector_id": collector.collector_id,
                "collector_name": collector.name,
                "collector_type": collector._settings.collector.platform,
                "collector_period": collector._get_period_seconds.return_value,
            }
            pingalive_cls.assert_called_once_with(
                collector.oaev_api,
                expected_config,
                collector.logger,
                "collector",
            )

    def test_start_calls_pingalive_thread_start(self) -> None:
        collector = self._build_collector()
        parse_args, scheduler_patch = self._patch_start_runtime()

        with parse_args, scheduler_patch, patch(
            "collectors_sdk._core.base_collector.collector.PingAlive",
            create=True,
        ) as pingalive_cls:
            pingalive_thread = MagicMock()
            pingalive_cls.return_value = pingalive_thread

            collector.start()

            pingalive_thread.start.assert_called_once_with()

    def test_start_passes_collector_api_and_logger_to_pingalive(self) -> None:
        collector = self._build_collector()
        parse_args, scheduler_patch = self._patch_start_runtime()

        with parse_args, scheduler_patch, patch(
            "collectors_sdk._core.base_collector.collector.PingAlive",
            create=True,
        ) as pingalive_cls:
            collector.start()

            pingalive_cls.assert_called()
            args, _ = pingalive_cls.call_args
            assert args[0] is collector.oaev_api
            assert args[2] is collector.logger
