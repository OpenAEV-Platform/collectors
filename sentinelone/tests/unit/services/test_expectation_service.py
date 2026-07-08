import unittest
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
        self.assertIsInstance(service.failure_tracker, module.defaultdict)
        self.assertEqual(service.max_failure, 5)
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

    def test_update_failures(self, *_):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)

        uuid_zero = "6b7d53b5-2828-4be8-a797-a5193c615ec5"
        result_zero = MagicMock()
        result_zero.is_valid = True
        result_zero.expectation_id = uuid_zero

        uuid_one = "2930a07a-7077-478b-a7d0-27699a03edf3"
        result_one = MagicMock()
        result_one.is_valid = False
        result_one.expectation_id = uuid_one
        service.failure_tracker[uuid_one] = 2

        uuid_two = "adccb725-9769-4856-bbc3-1cdc1ff98a26"
        result_two = MagicMock()
        result_two.is_valid = False
        result_two.expectation_id = uuid_two
        service.failure_tracker[uuid_two] = 5

        m_results = [result_zero, result_one, result_two]

        results = service._update_failures(m_results)

        self.assertNotEqual(len(m_results), len(results))
        self.assertEqual(len(results), 2)
        self.assertEqual(service.failure_tracker[uuid_one], 3)
        self.assertNotIn(uuid_two, service.failure_tracker)
        self.assertNotIn(uuid_zero, service.failure_tracker)

    def test_update_date_in_case_of_failures(self, *_):
        config = MagicMock()

        service = module.SentinelOneExpectationService(config=config)

        uuid = UUID("feb4be6f-72c7-4212-8984-a7d7c42178f0")
        service.failure_tracker[str(uuid)] = 1

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
