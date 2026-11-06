import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import src.collector.collector as module
from pyoaev.apis.inject_expectation.model import LoggingExpectation
from pyoaev.signatures.types import SignatureTypes
from src.collector.logging_manager import LoggingManager, LoggingSummary
from src.services.logging_fetch import (
    LoggingApiError,
    LoggingAuthError,
    LoggingIndexCheck,
    LoggingMalformed,
)
from src.services.logging_query import (
    LOGGING_QUERY_TEMPLATE,
    LoggingQuery,
    build_logging_query,
)
from src.services.logging_trace import LoggingTraceBuilder

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
}


class TestCollector(unittest.TestCase):
    @patch.object(module.Collector, "_process_callback")
    @patch.object(module, "SplunkESConfig")
    def test_init(self, m_splunk_es_config, m_process_callback):
        m_splunk_es_config.return_value = MagicMock()
        m_splunk_es_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        module.Collector()

        m_splunk_es_config.assert_called_once()
        m_splunk_es_config.return_value.load.to_daemon_config.assert_called_once()

    @patch.object(module, "SplunkESConfig")
    def test_process_callback(self, m_splunk_es_config):
        m_splunk_es_config.return_value = MagicMock()
        m_splunk_es_config.return_value.load.to_daemon_config.return_value = (
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
    @patch.object(module, "SplunkESConfig")
    def test_process_callback_keyboard_interrupt(self, m_splunk_es_config, m_exit):
        m_splunk_es_config.return_value = MagicMock()
        m_splunk_es_config.return_value.load.to_daemon_config.return_value = (
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
    @patch.object(module, "SplunkESConfig")
    def test_process_callback_system_exit(self, m_splunk_es_config, m_exit):
        m_splunk_es_config.return_value = MagicMock()
        m_splunk_es_config.return_value.load.to_daemon_config.return_value = (
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
    with patch.object(module, "SplunkESConfig") as m_splunk_es_config:
        config = m_splunk_es_config.return_value.load
        config.to_daemon_config.return_value = daemon_config_data
        config.splunk_es.logging_enabled = logging_enabled
        config.splunk_es.logging_indexes = "sysmon,wineventlog"
        config.splunk_es.logging_query_template = None
        return module.Collector()


SEARCHABLE = LoggingIndexCheck(found=["sysmon", "wineventlog"], missing=[])


def _setup(collector: module.Collector, index_check: object = SEARCHABLE) -> None:
    """Run the collector setup with the Splunk services mocked.

    Args:
        collector: The collector to set up.
        index_check: What the Logging index check returns, or raises when
            it is an exception.

    """
    service = MagicMock()
    service.return_value.client_api.logging_template = LOGGING_QUERY_TEMPLATE
    check = service.return_value.client_api.check_logging_indexes
    if isinstance(index_check, BaseException):
        check.side_effect = index_check
    else:
        check.return_value = index_check
    with (
        patch.object(module, "SplunkESExpectationService", service),
        patch.object(module, "SplunkESTraceService"),
        patch.object(module, "GenericExpectationHandler"),
        patch.object(module, "GenericExpectationManager"),
        patch.object(module, "OpenAEVDetectionHelper"),
        patch.object(module.Collector, "get_id", return_value="collector-1"),
    ):
        collector._setup()


def _logging_expectation(signatures: list[tuple[str, str]]) -> LoggingExpectation:
    """Build a pyoaev LOGGING expectation, as the platform sends it."""
    return LoggingExpectation(
        inject_expectation_id=uuid4(),
        inject_expectation_signatures=[
            {"type": kind, "value": value} for kind, value in signatures
        ],
        api_client=MagicMock(),
    )


class TestCollectorLogging(unittest.TestCase):
    """The Logging pass is opt-in and never stops the Detection pass."""

    def test_logging_disabled_declares_detection_and_prevention(self):
        collector = _collector(logging_enabled=False)

        self.assertEqual(
            collector._supported_expectation_types, ["DETECTION", "PREVENTION"]
        )

    def test_logging_disabled_creates_no_manager(self):
        collector = _collector(logging_enabled=False)

        with patch.object(module.Collector, "_create_logging_manager") as m_create:
            _setup(collector)

        m_create.assert_not_called()
        self.assertIsNone(collector.logging_manager)

    def test_logging_flag_must_be_true_not_just_set(self):
        # A MagicMock config, as in the other tests, must not enable Logging.
        with patch.object(module, "SplunkESConfig") as m_splunk_es_config:
            m_splunk_es_config.return_value.load.to_daemon_config.return_value = (
                daemon_config_data
            )
            collector = module.Collector()

        self.assertFalse(collector.logging_enabled)

    def test_logging_enabled_declares_logging(self):
        collector = _collector(logging_enabled=True)

        self.assertEqual(
            collector._supported_expectation_types,
            ["DETECTION", "PREVENTION", "LOGGING"],
        )

    def test_logging_enabled_creates_the_manager(self):
        collector = _collector(logging_enabled=True)
        logging_manager = MagicMock()

        with patch.object(
            module.Collector, "_create_logging_manager", return_value=logging_manager
        ):
            _setup(collector)

        self.assertIs(collector.logging_manager, logging_manager)

    def test_logging_runs_before_detection(self):
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
            ["logging_manager.process", "expectation_manager.process_expectations"],
        )

    def test_logging_failure_does_not_stop_detection(self):
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
            suspended=True,
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
            "suspended",
        ):
            self.assertIn(part, line)

    @patch.object(module.os, "_exit")
    def test_keyboard_interrupt_in_logging_still_stops_the_collector(self, m_exit):
        collector = _collector(logging_enabled=True)
        collector.logging_manager = MagicMock()
        collector.logging_manager.process.side_effect = KeyboardInterrupt()
        collector.expectation_manager = MagicMock()

        collector._process_callback()

        m_exit.assert_called_with(0)

    def test_suspension_withdraws_logging_and_detection_goes_on(self):
        collector = _collector(logging_enabled=True)
        api = MagicMock()
        api.inject_expectation.logging_expectation_models_for_source.return_value = [
            MagicMock(
                inject_expectation_id="exp-1",
                inject_expectation_signatures=[
                    MagicMock(type=SignatureTypes.SIG_TYPE_END_DATE, value="x")
                ],
            )
        ]
        collector.logging_manager = LoggingManager(
            oaev_api=api,
            collector_id="collector-1",
            build_query=MagicMock(),
            fetch_events=MagicMock(return_value=LoggingAuthError(403, "forbidden")),
            trace_builder=MagicMock(),
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

    def test_logging_disabled_makes_no_logging_call(self):
        collector = _collector(logging_enabled=False)
        _setup(collector)

        with (
            patch.object(
                collector.api.inject_expectation,
                "logging_expectation_models_for_source",
            ) as m_fetch,
            patch.object(collector.logger, "error") as error,
        ):
            collector._process_callback()

        m_fetch.assert_not_called()
        error.assert_not_called()
        collector.expectation_manager.process_expectations.assert_called_once()

    def test_logging_manager_is_wired_to_the_splunk_search(self):
        collector = _collector(logging_enabled=True)
        config = collector.config_instance
        config.collector.period = timedelta(minutes=2)
        config.splunk_es.logging_max_interval = timedelta(minutes=30)
        expectation = _logging_expectation(
            [("end_date", "2026-11-03T10:05:00Z"), ("source_ipv4_address", "10.0.0.1")]
        )

        with patch.object(module, "build_logging_query") as build_logging_query:
            _setup(collector)
            manager = collector.logging_manager
            manager.build_query(expectation)

        self.assertIsInstance(manager, LoggingManager)
        build_logging_query.assert_called_once_with(
            [
                {"type": "end_date", "value": "2026-11-03T10:05:00Z"},
                {"type": "source_ipv4_address", "value": "10.0.0.1"},
            ],
            "sysmon,wineventlog",
            LOGGING_QUERY_TEMPLATE,
        )
        self.assertIs(
            manager.fetch_events,
            collector.splunkes_service.client_api.fetch_logging_events,
        )
        self.assertEqual(manager.period, timedelta(minutes=2))
        self.assertEqual(manager.max_interval, timedelta(minutes=30))
        self.assertEqual(manager.collector_id, "collector-1")
        self.assertIsInstance(manager.trace_builder, LoggingTraceBuilder)
        self.assertIs(manager.trace_builder.config, collector.config_instance)
        manager.on_suspend()
        self.assertEqual(
            collector._supported_expectation_types, ["DETECTION", "PREVENTION"]
        )

    def test_logging_manager_builds_the_splunk_query_of_an_expectation(self):
        # Not mocked: the builder reads the pyoaev signatures as converted here.
        collector = _collector(logging_enabled=True)
        config = collector.config_instance
        config.collector.period = timedelta(minutes=1)
        config.splunk_es.logging_max_interval = timedelta(minutes=15)
        signatures = [
            ("start_date", "2026-11-03T10:00:00Z"),
            ("end_date", "2026-11-03T10:05:00Z"),
            ("source_ipv4_address", "10.0.0.1"),
        ]
        _setup(collector)

        query = collector.logging_manager.build_query(_logging_expectation(signatures))

        self.assertIsInstance(query, LoggingQuery)
        self.assertEqual(query.source_ips, ["10.0.0.1"])
        self.assertEqual(query.latest - query.earliest, 300)
        # Compared with the builder, not with its SPL template.
        self.assertEqual(
            query,
            build_logging_query(
                [{"type": t, "value": v} for t, v in signatures],
                "sysmon,wineventlog",
                LOGGING_QUERY_TEMPLATE,
            ),
        )

    def test_index_names_are_not_logged_at_info_level(self):
        collector = _collector(logging_enabled=True)
        config = collector.config_instance
        config.collector.period = timedelta(minutes=1)
        config.splunk_es.logging_max_interval = timedelta(minutes=15)
        collector.config_instance.splunk_es.logging_indexes = "secret_idx_a,idx_b,idx_c"

        with patch.object(collector.logger, "info") as info:
            _setup(collector)
            collector.logging_manager.oaev_api = MagicMock()
            collector.logging_manager.oaev_api.inject_expectation.logging_expectation_models_for_source.return_value = (
                []
            )
            collector._process_callback()

        messages = " ".join(str(c.args) for c in info.call_args_list)
        self.assertIn("3 indexes", messages)
        for name in ("secret_idx_a", "idx_b", "idx_c"):
            self.assertNotIn(name, messages)

    def test_logging_setup_failure_withdraws_logging_and_keeps_detection(self):
        # AttributeError: a renamed setting or a missing Splunk client method.
        for error in (RuntimeError("boom"), AttributeError("no fetch")):
            with self.subTest(error=type(error).__name__):
                collector = _collector(logging_enabled=True)

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

    def test_missing_logging_setting_fails_the_setup_not_each_search(self):
        collector = _collector(logging_enabled=True)
        del collector.config_instance.splunk_es.logging_max_interval

        _setup(collector)

        self.assertIsNone(collector.logging_manager)
        self.assertEqual(
            collector._supported_expectation_types, ["DETECTION", "PREVENTION"]
        )


class TestCollectorLoggingIndexCheck(unittest.TestCase):
    """The setup checks once that Splunk can search the Logging indexes."""

    @staticmethod
    def _collector() -> module.Collector:
        collector = _collector(logging_enabled=True)
        config = collector.config_instance
        config.collector.period = timedelta(minutes=1)
        config.splunk_es.logging_max_interval = timedelta(minutes=15)
        return collector

    def _assert_logging_kept(self, collector: module.Collector) -> None:
        self.assertIsInstance(collector.logging_manager, LoggingManager)
        self.assertEqual(
            collector._supported_expectation_types,
            ["DETECTION", "PREVENTION", "LOGGING"],
        )

    def _assert_logging_withdrawn(self, collector: module.Collector) -> None:
        self.assertIsNone(collector.logging_manager)
        self.assertEqual(
            collector._supported_expectation_types, ["DETECTION", "PREVENTION"]
        )
        self.assertIsNotNone(collector.oaev_detection_helper)

    def test_the_configured_indexes_are_checked(self):
        collector = self._collector()

        _setup(collector)

        check = collector.splunkes_service.client_api.check_logging_indexes
        check.assert_called_once_with("sysmon,wineventlog")
        self._assert_logging_kept(collector)

    def test_some_missing_indexes_keep_logging(self):
        # The client logs the missing ones; the others can still log events.
        collector = self._collector()

        _setup(collector, LoggingIndexCheck(found=["sysmon"], missing=["typo"]))

        self._assert_logging_kept(collector)

    def test_no_searchable_index_withdraws_logging(self):
        collector = self._collector()

        with patch.object(collector.logger, "error") as error:
            _setup(collector, LoggingIndexCheck(found=[], missing=["a", "b"]))

        self._assert_logging_withdrawn(collector)
        message = error.call_args.args[0]
        self.assertIn("None of the 2 Logging indexes can be searched", message)
        self.assertIn("LOGGING is withdrawn and Detection goes on", message)

    def test_refused_check_withdraws_logging_and_says_why(self):
        for error, answer in (
            (LoggingAuthError(403, "insufficient permissions"), "(HTTP 403: "),
            (LoggingAuthError(401), "(HTTP 401)"),
        ):
            with self.subTest(status=error.status_code):
                collector = self._collector()

                with patch.object(collector.logger, "error") as log_error:
                    _setup(collector, error)

                self._assert_logging_withdrawn(collector)
                message = log_error.call_args.args[0]
                self.assertIn(
                    f"Splunk refused the Logging index check {answer}", message
                )
                self.assertIn("LOGGING is withdrawn", message)

    def test_check_that_cannot_run_keeps_logging(self):
        # Splunk down or an odd answer at startup: the searches report it.
        for result in (
            LoggingApiError("Request failed: timeout"),
            LoggingMalformed("Response is not JSON"),
            RuntimeError("boom"),
            MagicMock(),
        ):
            with self.subTest(result=type(result).__name__):
                collector = self._collector()

                with patch.object(collector.logger, "warning") as warning:
                    _setup(collector, result)

                self._assert_logging_kept(collector)
                message = warning.call_args.args[0]
                self.assertIn("Could not check the Logging indexes", message)
                self.assertIn("Logging goes on", message)

    def test_failed_setup_skips_the_check(self):
        collector = self._collector()

        with patch.object(
            module.Collector, "_create_logging_manager", side_effect=RuntimeError
        ):
            _setup(collector)

        check = collector.splunkes_service.client_api.check_logging_indexes
        check.assert_not_called()

    def test_logging_disabled_skips_the_check(self):
        collector = _collector(logging_enabled=False)

        _setup(collector)

        check = collector.splunkes_service.client_api.check_logging_indexes
        check.assert_not_called()
