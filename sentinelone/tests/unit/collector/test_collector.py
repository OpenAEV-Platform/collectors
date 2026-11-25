import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import src.collector.collector as module
from pyoaev.apis.inject_expectation.model import LoggingExpectation
from src.collector.logging_manager import LoggingManager, LoggingSummary
from src.services.logging_fetch import LoggingAuthError
from src.services.logging_query import build_logging_query

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
}


class TestCollector(unittest.TestCase):
    @patch.object(module.Collector, "_process_callback")
    @patch.object(module, "SentinelOneConfig")
    def test_init(self, m_sentinel_one_config, m_process_callback):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        module.Collector()

        m_sentinel_one_config.assert_called_once()
        m_sentinel_one_config.return_value.load.to_daemon_config.assert_called_once()

    @patch.object(module, "SentinelOneConfig")
    def test_process_callback(self, m_sentinel_one_config):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        collector = module.Collector()
        expectation_manager = MagicMock()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()

        expectation_manager.process_expectations.assert_called_with(
            detection_helper=oaev_detection_helper
        )

    @patch.object(module.os, "_exit")
    @patch.object(module, "SentinelOneConfig")
    def test_process_callback_keyboard_interrupt(self, m_sentinel_one_config, m_exit):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        collector = module.Collector()
        expectation_manager = MagicMock()
        expectation_manager.process_expectations.side_effect = KeyboardInterrupt()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()
        expectation_manager.process_expectations.assert_called_with(
            detection_helper=oaev_detection_helper
        )
        m_exit.assert_called_with(0)

    @patch.object(module.os, "_exit")
    @patch.object(module, "SentinelOneConfig")
    def test_process_callback_system_exit(self, m_sentinel_one_config, m_exit):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        collector = module.Collector()
        expectation_manager = MagicMock()
        expectation_manager.process_expectations.side_effect = SystemExit()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()
        expectation_manager.process_expectations.assert_called_with(
            detection_helper=oaev_detection_helper
        )
        m_exit.assert_called_with(0)


def _collector(logging_enabled: bool) -> module.Collector:
    """Build a collector whose config enables Logging or not."""
    with patch.object(module, "SentinelOneConfig") as m_sentinel_one_config:
        config = m_sentinel_one_config.return_value.load
        config.to_daemon_config.return_value = daemon_config_data
        config.sentinelone.logging_enabled = logging_enabled
        return module.Collector()


class TestCollectorLoggingDeclaration(unittest.TestCase):
    """LOGGING is declared to the platform only when Logging is enabled."""

    def test_logging_disabled_declares_detection_and_prevention(self):
        collector = _collector(logging_enabled=False)

        self.assertEqual(
            collector._supported_expectation_types, ["DETECTION", "PREVENTION"]
        )

    def test_logging_enabled_declares_logging(self):
        collector = _collector(logging_enabled=True)

        self.assertEqual(
            collector._supported_expectation_types,
            ["DETECTION", "PREVENTION", "LOGGING"],
        )

    def test_logging_flag_must_be_true_not_just_set(self):
        # A MagicMock config, as in the other tests, must not enable Logging.
        with patch.object(module, "SentinelOneConfig") as m_sentinel_one_config:
            m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
                daemon_config_data
            )
            collector = module.Collector()

        self.assertFalse(collector.logging_enabled)
        self.assertEqual(
            collector._supported_expectation_types, ["DETECTION", "PREVENTION"]
        )


def _setup(collector: module.Collector, self_hosted: bool = False) -> None:
    """Run the collector setup with the SentinelOne services mocked."""
    service = MagicMock()
    service.return_value.client_api.is_self_hosted = self_hosted
    service.return_value.client_api.base_url = "https://s1.example.com"
    with (
        patch.object(module, "SentinelOneExpectationService", service),
        patch.object(module, "SentinelOneTraceService"),
        patch.object(module, "GenericExpectationHandler"),
        patch.object(module, "GenericExpectationManager"),
        patch.object(module, "OpenAEVDetectionHelper"),
        patch.object(module.Collector, "get_id", return_value="collector-1"),
    ):
        collector._setup()


def _configured(logging_enabled: bool = True) -> module.Collector:
    """Build a collector with a real period and max interval."""
    collector = _collector(logging_enabled=logging_enabled)
    collector.config_instance.collector.period = timedelta(minutes=2)
    collector.config_instance.sentinelone.logging_max_interval = timedelta(minutes=30)
    return collector


def _logging_expectation(signatures: list[tuple[str, str]]) -> LoggingExpectation:
    """Build a pyoaev LOGGING expectation, as the platform sends it."""
    return LoggingExpectation(
        inject_expectation_id=uuid4(),
        inject_expectation_signatures=[
            {"type": kind, "value": value} for kind, value in signatures
        ],
        api_client=MagicMock(),
    )


class TestCollectorLoggingPass(unittest.TestCase):
    """The Logging pass is opt-in, runs after Detection, and never stops it."""

    def test_logging_disabled_creates_no_manager(self):
        collector = _configured(logging_enabled=False)

        with patch.object(module.Collector, "_create_logging_manager") as m_create:
            _setup(collector)

        m_create.assert_not_called()
        self.assertIsNone(collector.logging_manager)

    def test_logging_runs_after_detection(self):
        collector = _collector(logging_enabled=True)
        calls = MagicMock()
        collector.logging_manager = calls.logging_manager
        collector.expectation_manager = calls.expectation_manager
        collector.oaev_detection_helper = MagicMock()

        collector._process_callback()

        passes = [
            name
            for name, _, _ in calls.mock_calls
            if name
            in ("logging_manager.process", "expectation_manager.process_expectations")
        ]
        self.assertEqual(
            passes,
            ["expectation_manager.process_expectations", "logging_manager.process"],
        )

    def test_detection_failure_still_runs_logging(self):
        collector = _collector(logging_enabled=True)
        collector.logging_manager = MagicMock()
        collector.expectation_manager = MagicMock()
        collector.expectation_manager.process_expectations.side_effect = RuntimeError(
            "boom"
        )
        collector.oaev_detection_helper = MagicMock()

        with self.assertRaises(module.CollectorProcessingError):
            collector._process_callback()

        collector.logging_manager.process.assert_called_once_with()

    @patch.object(module.os, "_exit")
    def test_stop_request_during_detection_skips_logging(self, m_exit):
        collector = _collector(logging_enabled=True)
        collector.logging_manager = MagicMock()
        collector.expectation_manager = MagicMock()
        collector.expectation_manager.process_expectations.side_effect = (
            KeyboardInterrupt()
        )
        collector.oaev_detection_helper = MagicMock()

        collector._process_callback()

        collector.logging_manager.process.assert_not_called()
        m_exit.assert_called_with(0)

    @patch.object(module.os, "_exit")
    def test_stop_request_during_logging_stops_the_collector(self, m_exit):
        collector = _collector(logging_enabled=True)
        collector.logging_manager = MagicMock()
        collector.logging_manager.process.side_effect = KeyboardInterrupt()
        collector.expectation_manager = MagicMock()
        collector.oaev_detection_helper = MagicMock()

        collector._process_callback()

        collector.expectation_manager.process_expectations.assert_called_once()
        m_exit.assert_called_with(0)

    def test_logging_failure_does_not_stop_the_cycle(self):
        for error in (RuntimeError("boom"), ValueError("bad"), AttributeError("x")):
            with self.subTest(error=type(error).__name__):
                collector = _collector(logging_enabled=True)
                collector.logging_manager = MagicMock()
                collector.logging_manager.process.side_effect = error
                collector.expectation_manager = MagicMock()
                collector.oaev_detection_helper = MagicMock()

                collector._process_callback()

                collector.expectation_manager.process_expectations.assert_called_once()

    def test_logging_pass_summary_is_logged(self):
        collector = _collector(logging_enabled=True)
        collector.logging_manager = MagicMock()
        collector.logging_manager.process.return_value = LoggingSummary(
            fetched=11,
            logged=12,
            deferred=13,
            over_budget=14,
            skipped_no_end_date=15,
            unqueryable=16,
            no_match=17,
            errors=18,
            rate_limited=True,
        )
        collector.expectation_manager = MagicMock()
        collector.oaev_detection_helper = MagicMock()

        with patch.object(collector.logger, "info") as info:
            collector._process_callback()

        line = next(
            c.args[0] for c in info.call_args_list if "Logging pass" in c.args[0]
        )
        for part in (
            "11 fetched",
            "12 logged",
            "13 deferred",
            "14 over budget",
            "15 without end date",
            "16 unqueryable",
            "17 no match",
            "18 errors",
            "stopped by the rate limit",
        ):
            self.assertIn(part, line)

    def test_suspension_withdraws_logging_and_detection_goes_on(self):
        collector = _collector(logging_enabled=True)
        api = MagicMock()
        api.inject_expectation.logging_expectation_models_for_source.return_value = [
            _logging_expectation([("end_date", "2026-11-03T10:05:00Z")])
        ]
        collector.logging_manager = LoggingManager(
            oaev_api=api,
            collector_id="collector-1",
            build_query=MagicMock(),
            fetch_events=MagicMock(return_value=LoggingAuthError(403, "forbidden")),
            build_trace=MagicMock(),
            period=timedelta(minutes=1),
            max_interval=timedelta(minutes=15),
            on_suspend=collector._withdraw_logging,
        )
        collector.expectation_manager = MagicMock()
        collector.oaev_detection_helper = MagicMock()
        # As after registration: the ping payload must change too.
        collector._registration_config = {
            "collector_supported_expectation_types": [
                "DETECTION",
                "PREVENTION",
                "LOGGING",
            ]
        }

        collector._process_callback()

        self.assertEqual(
            collector._registration_config["collector_supported_expectation_types"],
            ["DETECTION", "PREVENTION"],
        )
        collector.expectation_manager.process_expectations.assert_called_once()

    def test_logging_manager_is_wired_to_the_event_search(self):
        for self_hosted in (False, True):
            with self.subTest(self_hosted=self_hosted):
                collector = _configured()
                _setup(collector, self_hosted=self_hosted)
                manager = collector.logging_manager
                fetcher = collector.sentinelone_service.deep_visibility_fetcher
                query, deadline = MagicMock(), MagicMock()

                with patch.object(module, "fetch_logging_events") as fetch:
                    manager.fetch_events(query, deadline)

                self.assertIsInstance(manager, LoggingManager)
                fetch.assert_called_once_with(fetcher, query, deadline)
                self.assertEqual(manager.period, timedelta(minutes=2))
                self.assertEqual(manager.max_interval, timedelta(minutes=30))
                self.assertEqual(manager.collector_id, "collector-1")
                manager.on_suspend()
                self.assertEqual(
                    collector._supported_expectation_types, ["DETECTION", "PREVENTION"]
                )

    def test_logging_manager_builds_the_query_of_the_backend(self):
        signatures = [
            ("start_date", "2026-11-03T10:00:00Z"),
            ("end_date", "2026-11-03T10:05:00Z"),
            ("source_ipv4_address", "10.0.0.1"),
        ]
        for self_hosted in (False, True):
            with self.subTest(self_hosted=self_hosted):
                collector = _configured()
                _setup(collector, self_hosted=self_hosted)

                query = collector.logging_manager.build_query(
                    _logging_expectation(signatures)
                )

                self.assertEqual(
                    query,
                    build_logging_query(
                        [{"type": t, "value": v} for t, v in signatures], self_hosted
                    ),
                )

    def test_logging_manager_builds_the_trace_with_the_console_url(self):
        collector = _configured()
        _setup(collector, self_hosted=True)
        match, query = MagicMock(), MagicMock()

        with patch.object(module, "build_logging_trace") as build:
            collector.logging_manager.build_trace(match, query, "exp-1", "collector-1")

        build.assert_called_once_with(
            match, query, "exp-1", "collector-1", "https://s1.example.com", True
        )

    def test_logging_setup_failure_withdraws_logging_and_keeps_detection(self):
        for error in (RuntimeError("boom"), AttributeError("no fetcher")):
            with self.subTest(error=type(error).__name__):
                collector = _configured()

                with patch.object(
                    module.Collector, "_create_logging_manager", side_effect=error
                ):
                    _setup(collector)

                self.assertIsNone(collector.logging_manager)
                self.assertEqual(
                    collector._supported_expectation_types,
                    ["DETECTION", "PREVENTION"],
                )
                self.assertIsNotNone(collector.oaev_detection_helper)
