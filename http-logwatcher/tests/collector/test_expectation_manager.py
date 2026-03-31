import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.collector.expectation_manager as module


class GenericExpectationManagerTest(unittest.TestCase):
    def test_generic_expectation_manager_init(self):
        """
        testing the proper init of the GenericExpectationManager object
        """
        oaev_api = MagicMock()
        collector_id = sentinel.collector_id
        expectation_service = MagicMock()
        trace_service = MagicMock()

        generic_expectation_manager = module.GenericExpectationManager(
            oaev_api=oaev_api,
            collector_id=collector_id,
            expectation_service=expectation_service,
            trace_service=trace_service,
        )

        self.assertIs(
            generic_expectation_manager.oaev_api,
            oaev_api,
        )
        self.assertIs(
            generic_expectation_manager.collector_id,
            sentinel.collector_id,
        )
        self.assertIs(
            generic_expectation_manager.expectation_service,
            expectation_service,
        )
        self.assertIs(
            generic_expectation_manager.trace_manager.trace_service,
            trace_service,
        )

    @patch.object(module.GenericExpectationManager, "_fetch_expectations")
    def test_generic_expectation_manager_process_expectations_empty(
        self, m_fetch_expectations
    ):
        """testing process_exepectations behavior against empty expectation"""
        oaev_api = MagicMock()
        collector_id = sentinel.collector_id
        expectation_service = MagicMock()
        trace_service = MagicMock()

        generic_expectation_manager = module.GenericExpectationManager(
            oaev_api=oaev_api,
            collector_id=collector_id,
            expectation_service=expectation_service,
            trace_service=trace_service,
        )

        m_fetch_expectations.return_value = []
        detection_helper = MagicMock()
        summary = generic_expectation_manager.process_expectations(
            detection_helper=detection_helper,
        )

        m_fetch_expectations.assert_called_once()
        self.assertEqual(summary.processed, 0)
        self.assertEqual(summary.valid, 0)
        self.assertEqual(summary.invalid, 0)
        self.assertEqual(summary.skipped, 0)
        self.assertEqual(summary.total_processing_time, None)
