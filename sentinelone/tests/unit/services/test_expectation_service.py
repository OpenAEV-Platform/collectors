import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import ANY, MagicMock, patch
from uuid import UUID

import src.services.expectation_service as module


@patch.object(module, "FetcherDeepVisibility")
@patch.object(module, "FetcherThreatEvents")
@patch.object(module, "FetcherThreat")
@patch.object(module, "SentinelOneConverter")
@patch.object(module, "SentinelOneClientAPI")
class TestSentinelOneExpectationService(unittest.TestCase):
    def test_init(
        self,
        m_api,
        m_converter,
        m_fetcher_threat,
        m_fetcher_threat_events,
        m_fetcher_deep_visibility,
    ):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)

        self.assertEqual(service.client_api, m_api.return_value)
        self.assertEqual(service.converter, m_converter.return_value)
        self.assertEqual(service.batch_size, config.sentinelone.expectation_batch_size)
        self.assertEqual(
            service.enable_deep_visibility_search,
            config.sentinelone.enable_deep_visibility_search,
        )
        self.assertEqual(
            service.disable_strict_end_date, config.sentinelone.disable_strict_end_date
        )
        self.assertEqual(service.threat_fetcher, m_fetcher_threat.return_value)
        self.assertEqual(
            service.threat_events_fetcher, m_fetcher_threat_events.return_value
        )
        self.assertEqual(
            service.deep_visibility_fetcher, m_fetcher_deep_visibility.return_value
        )
        self.assertIsInstance(service.first_attempt_at, dict)
        self.assertEqual(service.retry_window, config.sentinelone.retry_window)
        m_api.assert_called_once_with(config)
        m_converter.assert_called_once()
        m_fetcher_threat.assert_called_once_with(m_api.return_value)
        m_fetcher_threat_events.assert_called_once_with(m_api.return_value)
        m_fetcher_deep_visibility.assert_called_once_with(m_api.return_value)

    def test_get_supported_signatures(self, *_):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)

        self.assertEqual(
            service.get_supported_signatures(),
            [
                module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
                module.SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS,
                module.SignatureTypes.SIG_TYPE_END_DATE,
            ],
        )

    def test_expectation_does_not_match_when_signature_data_is_missing(
        self,
        _m_api,
        m_converter,
        *_,
    ):
        """A required signature with no converted data is a clean non-match."""
        config = MagicMock()
        service = module.SentinelOneExpectationService(config=config)
        service.logger = MagicMock()

        expectation = MagicMock()
        signature = MagicMock()
        signature.type = module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME
        signature.value = "expected-parent.exe"
        expectation.inject_expectation_signatures = [signature]

        threat = MagicMock()
        threat.threat_id = "threat-without-parent-process"
        m_converter.return_value.convert_threats_to_oaev.return_value = [
            {
                "target_hostname_address": {
                    "type": "simple",
                    "data": ["host.example.com"],
                }
            }
        ]
        detection_helper = MagicMock()

        result = service._expectation_matches_threat_data(
            expectation, threat, [], detection_helper
        )

        self.assertFalse(result)
        logged_calls = " ".join(str(call) for call in service.logger.method_calls)
        self.assertNotIn("KeyError", logged_calls)
        detection_helper.match_alert_elements.assert_not_called()

    @patch.object(module.SentinelOneExpectationService, "_process_expectation_batch")
    @patch.object(module.SentinelOneExpectationService, "_create_expectation_batches")
    def test_handle_batch_expectations(
        self, m_create_expectation_batches, m_process_expectation_batch, *_
    ):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)

        expectations = MagicMock()
        detection_helper = MagicMock()
        batch = MagicMock()
        batches = [batch]
        m_create_expectation_batches.return_value = batches, 0
        batch_results = [MagicMock()]
        m_process_expectation_batch.return_value = batch_results

        all_results, skipped_count = service.handle_batch_expectations(
            expectations, detection_helper
        )

        m_create_expectation_batches.assert_called_once_with(expectations)
        m_process_expectation_batch.assert_called_with(batch, detection_helper, 1)
        self.assertEqual(all_results, batch_results)

    @patch.object(module, "SignatureExtractor")
    def test_create_expectation_batches(self, m_signature_extractor, *_):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.disable_strict_end_date = False

        expectation_zero = MagicMock()
        expectations = [expectation_zero]
        m_signature_extractor.extract_end_date.return_value = 1

        batches, skipped_count = service._create_expectation_batches(expectations)

        m_signature_extractor.extract_end_date.assert_called_once_with(
            [expectation_zero]
        )
        self.assertEqual(batches, [[expectation_zero]])

    @patch.object(module, "SignatureExtractor")
    def test_get_fetch_time_window_with_start_date(self, m_signature_extractor, *_):
        """A valid start date anchors the window start; the window ends at
        now.

        The signature end date is no longer read for this window.
        """
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.client_api.time_window = timedelta(hours=1)

        batch = [MagicMock()]
        end_date = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        start_date = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        m_signature_extractor.extract_start_date.return_value = start_date

        start, end = service._get_fetch_time_window(batch)

        m_signature_extractor.extract_end_date.assert_not_called()
        m_signature_extractor.extract_start_date.assert_called_once_with(batch)
        self.assertEqual(start, start_date)
        self.assertNotEqual(end, end_date)
        self.assertLess(abs(end - datetime.now(timezone.utc)), timedelta(minutes=1))

    @patch.object(module, "SignatureExtractor")
    def test_get_fetch_time_window_without_start_date(self, m_signature_extractor, *_):
        """Without a start date the threat window falls back to
        now - SENTINELONE_TIME_WINDOW.

        The window spans now - SENTINELONE_TIME_WINDOW to now.
        """
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.client_api.time_window = timedelta(hours=1)

        batch = [MagicMock()]
        m_signature_extractor.extract_start_date.return_value = None

        start, end = service._get_fetch_time_window(batch)

        m_signature_extractor.extract_end_date.assert_not_called()
        self.assertEqual(start, end - timedelta(hours=1))
        self.assertLess(abs(end - datetime.now(timezone.utc)), timedelta(minutes=1))

    @patch.object(module, "SignatureExtractor")
    def test_get_fetch_time_window_with_start_date_in_future(
        self, m_signature_extractor, *_
    ):
        """A start date in the future is anomalous; the window falls back
        to now - SENTINELONE_TIME_WINDOW.

        The window spans now - SENTINELONE_TIME_WINDOW to now.
        """
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.client_api.time_window = timedelta(hours=1)

        batch = [MagicMock()]
        m_signature_extractor.extract_start_date.return_value = datetime(
            2999, 1, 1, 12, 0, 0, tzinfo=timezone.utc
        )

        start, end = service._get_fetch_time_window(batch)

        self.assertEqual(start, end - timedelta(hours=1))
        self.assertLess(abs(end - datetime.now(timezone.utc)), timedelta(minutes=1))

    def test_get_deep_visibility_fetch_window(self, *_):
        """The DV event window ignores the signature dates and spans exactly
        the configured lookback, ending at the reference time."""
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.client_api.deep_visibility_lookback = timedelta(hours=6)

        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        start, end = service._get_deep_visibility_fetch_window(now=now)

        self.assertEqual(end, now)
        self.assertEqual(start, now - timedelta(hours=6))

    def test_update_failures(self, *_):
        """Valid results close the lifecycle; in-window failures stay held
        pending; failures after the window are the final attempt (verdict)."""
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.retry_window = timedelta(minutes=10)

        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        uuid_zero = "6b7d53b5-2828-4be8-a797-a5193c615ec5"
        result_zero = MagicMock()
        result_zero.is_valid = True
        result_zero.expectation_id = uuid_zero
        service.first_attempt_at[uuid_zero] = now - timedelta(minutes=2)

        uuid_one = "2930a07a-7077-478b-a7d0-27699a03edf3"
        result_one = MagicMock()
        result_one.is_valid = False
        result_one.expectation_id = uuid_one
        service.first_attempt_at[uuid_one] = now - timedelta(minutes=5)

        uuid_two = "adccb725-9769-4856-bbc3-1cdc1ff98a26"
        result_two = MagicMock()
        result_two.is_valid = False
        result_two.expectation_id = uuid_two
        service.first_attempt_at[uuid_two] = now - timedelta(minutes=15)

        m_results = [result_zero, result_one, result_two]

        with patch.object(
            module.SentinelOneExpectationService, "_now", return_value=now
        ):
            results = service._update_failures(m_results)

        self.assertNotEqual(len(m_results), len(results))
        self.assertEqual(len(results), 2)
        self.assertIn(result_zero, results)
        self.assertNotIn(result_one, results)
        self.assertIn(result_two, results)
        self.assertNotIn(uuid_zero, service.first_attempt_at)
        self.assertIn(uuid_one, service.first_attempt_at)
        self.assertNotIn(uuid_two, service.first_attempt_at)

    def test_update_failures_first_attempt_opens_retry_window(self, *_):
        """The first failed attempt opens the retry window anchored at that
        moment and emits no verdict (re-fetched on the next cycle)."""
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.retry_window = timedelta(minutes=10)

        now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        uuid = "1e0f7b3c-5a2d-4f8e-9c1b-2d3e4f5a6b7c"
        result = MagicMock()
        result.is_valid = False
        result.expectation_id = uuid

        with patch.object(
            module.SentinelOneExpectationService, "_now", return_value=now
        ):
            results = service._update_failures([result])

        self.assertEqual(results, [])
        self.assertIn(uuid, service.first_attempt_at)
        self.assertEqual(service.first_attempt_at[uuid], now)

    def test_update_failures_at_window_boundary_stays_pending(self, *_):
        """An attempt at exactly retry_window since the first attempt is still
        in-window (the boundary is inclusive); only the next cycle degrades."""
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)
        service.retry_window = timedelta(minutes=10)

        now = datetime(2024, 1, 1, 12, 10, 0, tzinfo=timezone.utc)
        uuid = "8c4a6d1e-3b7f-4e2a-8f0d-5c9e1b2a3d4f"
        result = MagicMock()
        result.is_valid = False
        result.expectation_id = uuid
        service.first_attempt_at[uuid] = now - timedelta(minutes=10)

        with patch.object(
            module.SentinelOneExpectationService, "_now", return_value=now
        ):
            results = service._update_failures([result])

        self.assertEqual(results, [])
        self.assertIn(uuid, service.first_attempt_at)

    def test_update_date_in_case_of_failures(self, *_):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)

        uuid = UUID("feb4be6f-72c7-4212-8984-a7d7c42178f0")
        service.first_attempt_at[str(uuid)] = datetime(
            2026, 5, 4, 3, 0, 0, tzinfo=timezone.utc
        )

        expectation = MagicMock()
        expectation.inject_expectation_id = uuid
        signature_type = MagicMock()
        signature_type.value = "end_date"
        signature_value = "2026-05-04 03:02:01.425813Z"
        signature = MagicMock()
        signature.type = signature_type
        signature.value = signature_value
        expectation.inject_expectation_signatures = [signature]

        batch = [expectation]

        with patch.object(
            module.SentinelOneExpectationService,
            "_now",
            return_value=datetime(2026, 5, 4, 3, 5, 0, tzinfo=timezone.utc),
        ):
            service._update_date_in_case_of_failures(batch)

        self.assertNotEqual(signature.value, signature_value)

    @patch.object(module.SentinelOneExpectationService, "_update_failures")
    @patch.object(
        module.SentinelOneExpectationService, "_match_threats_to_expectations"
    )
    @patch.object(
        module.SentinelOneExpectationService, "_fetch_threats_for_time_window"
    )
    @patch.object(
        module.SentinelOneExpectationService, "_extract_process_names_from_batch"
    )
    @patch.object(
        module.SentinelOneExpectationService, "_update_date_in_case_of_failures"
    )
    def test_process_expectation_batch(
        self,
        m_update_date_in_case_of_failures,
        m_extract_process_names_from_batch,
        m_fetch_threats_for_time_window,
        m_match_threats_to_expectations,
        m_update_failures,
        m_api,
        m_converter,
        m_fetcher_threat,
        m_fetcher_threat_events,
        m_fetcher_deep_visibility,
    ):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)

        expectation = MagicMock()
        batch = [expectation]
        detection_helper = MagicMock()
        batch_idx = 1
        threat = MagicMock()
        threats = [threat]
        m_fetch_threats_for_time_window.return_value = threats
        m_result = MagicMock()
        m_results = [m_result]
        m_match_threats_to_expectations.return_value = m_results
        m_updated_results = [m_result]
        m_update_failures.return_value = m_updated_results

        results = service._process_expectation_batch(batch, detection_helper, batch_idx)

        m_extract_process_names_from_batch.assert_called_once_with(batch)
        m_fetch_threats_for_time_window.assert_called_once_with(batch)
        m_fetcher_threat_events.return_value.fetch_events_for_threat.assert_called_once_with(
            threat, m_extract_process_names_from_batch.return_value
        )
        m_match_threats_to_expectations.assert_called_once_with(
            batch, threats, ANY, detection_helper
        )
        m_update_failures.assert_called_once_with(m_results)
        self.assertEqual(results, m_updated_results)
