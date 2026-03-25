import unittest
from unittest.mock import MagicMock

import src.models.expectation as module


class ExpectationResultTest(unittest.TestCase):
    def test_expectation_result_minimal_init(self):
        """ testing the minimal init of the ExpectationResult object (only the required elements) """
        expectation_id = "this-is-my-id"
        is_valid = True

        expectation_result = module.ExpectationResult(
            expectation_id=expectation_id,
            is_valid=is_valid,
        )

        self.assertIs(expectation_result.expectation_id, expectation_id)
        self.assertIs(expectation_result.is_valid, is_valid)
        self.assertIsNone(expectation_result.expectation)
        self.assertIsNone(expectation_result.matched_alerts)
        self.assertIsNone(expectation_result.error_message)
        self.assertIsNone(expectation_result.processing_time)

    def test_expectation_result_full_init(self):
        """ testing the full init of the ExpectationResult object (all parameters) """
        expectation_id = "this-is-my-id"
        is_valid = True
        expectation = MagicMock()
        matched_alerts = [
            {"foo": "bar"}
        ]
        error_message = "All your base are belong to us"
        processing_time=123.4

        expectation_result = module.ExpectationResult(
            expectation_id=expectation_id,
            is_valid=is_valid,
            expectation=expectation,
            matched_alerts=matched_alerts,
            error_message=error_message,
            processing_time=processing_time,
        )

        self.assertIs(expectation_result.expectation_id, expectation_id)
        self.assertIs(expectation_result.is_valid, is_valid)
        self.assertIs(expectation_result.expectation, expectation)
        self.assertEqual(expectation_result.matched_alerts, matched_alerts)
        self.assertIs(expectation_result.error_message, error_message)
        self.assertIs(expectation_result.processing_time, processing_time)

class ProcessingSummaryTest(unittest.TestCase):
    def test_processing_summary_minimal_init(self):
        """ testing the minimal init of the ProcessingSummary object (only the required elements) """
        processed = 6
        valid = 1
        invalid = 2
        skipped = 3

        processing_summary = module.ProcessingSummary(
            processed=processed,
            valid=valid,
            invalid=invalid,
            skipped=skipped,
        )

        self.assertIs(processing_summary.processed, processed)
        self.assertIs(processing_summary.valid, valid)
        self.assertIs(processing_summary.invalid, invalid)
        self.assertIs(processing_summary.skipped, skipped)
        self.assertIsNone(processing_summary.total_processing_time)

    def test_processing_summary_full_init(self):
        """ testing the full init of the ProcessingSummary object (all parameters) """
        processed = 6
        valid = 1
        invalid = 2
        skipped = 3
        total_processing_time = 123.4

        processing_summary = module.ProcessingSummary(
            processed=processed,
            valid=valid,
            invalid=invalid,
            skipped=skipped,
            total_processing_time=total_processing_time,
        )

        self.assertIs(processing_summary.processed, processed)
        self.assertIs(processing_summary.valid, valid)
        self.assertIs(processing_summary.invalid, invalid)
        self.assertIs(processing_summary.skipped, skipped)
        self.assertIs(processing_summary.total_processing_time, total_processing_time)
