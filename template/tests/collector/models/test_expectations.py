import unittest
from unittest.mock import ANY, MagicMock

import src.collector.models.expectations as module


class ExpectationResultTest(unittest.TestCase):
    def test_expectation_result_minimal_init(self):
        """
        testing the proper init of ExpectationResult with only required parameters
        """
        expectation_id = "id"
        is_valid = False

        expectation_result = module.ExpectationResult(
            expectation_id=expectation_id, is_valid=is_valid
        )

        self.assertEqual(expectation_id, expectation_result.expectation_id)
        self.assertEqual(is_valid, expectation_result.is_valid)
        self.assertIsNone(expectation_result.expectation)
        self.assertIsNone(expectation_result.matched_alerts)
        self.assertIsNone(expectation_result.error_message)
        self.assertIsNone(expectation_result.processing_time)

    def test_expectation_result_full_init(self):
        """
        testing the proper init of ExpectationResult with all parameters
        """
        expectation_id = "id"
        is_valid = False
        expectation = MagicMock()
        matched_alerts = [{"key": "valjue"}]
        error_message = "this is an error"
        processing_time = 12.34

        expectation_result = module.ExpectationResult(
            expectation_id=expectation_id,
            is_valid=is_valid,
            expectation=expectation,
            matched_alerts=matched_alerts,
            error_message=error_message,
            processing_time=processing_time,
        )

        self.assertEqual(expectation_id, expectation_result.expectation_id)
        self.assertEqual(is_valid, expectation_result.is_valid)
        self.assertEqual(expectation, expectation_result.expectation)
        self.assertEqual(matched_alerts, expectation_result.matched_alerts)
        self.assertEqual(error_message, expectation_result.error_message)
        self.assertEqual(processing_time, expectation_result.processing_time)

    def test_expectation_result_from_error(self):
        """
        testing the proper init of ExpectationResult with from_error
        """
        error = Exception("chat are we cooked")
        expectation = MagicMock()
        expectation.inject_expectation_id = "id"

        expectation_result = module.ExpectationResult.from_error(error, expectation)

        self.assertEqual("id", expectation_result.expectation_id)
        self.assertFalse(expectation_result.is_valid)
        self.assertEqual(expectation, expectation_result.expectation)
        self.assertIsNone(expectation_result.matched_alerts)
        self.assertEqual(str(error), expectation_result.error_message)
        self.assertIsNone(expectation_result.processing_time)

    def test_expectation_result_to_result_text(self):
        """
        testing the various output of the to_result_text
        """
        detection_expectation = MagicMock(spec=module.DetectionExpectation)
        prevention_expectation = MagicMock(spec=module.PreventionExpectation)
        id = "id"

        self.assertEqual(
            module.ExpectationResult(
                expectation_id=id, is_valid=True, expectation=detection_expectation
            ).to_result_text(),
            "Detected",
        )

        self.assertEqual(
            module.ExpectationResult(
                expectation_id=id, is_valid=False, expectation=detection_expectation
            ).to_result_text(),
            "Not Detected",
        )

        self.assertEqual(
            module.ExpectationResult(
                expectation_id=id, is_valid=True, expectation=prevention_expectation
            ).to_result_text(),
            "Prevented",
        )

        self.assertEqual(
            module.ExpectationResult(
                expectation_id=id, is_valid=False, expectation=prevention_expectation
            ).to_result_text(),
            "Not Prevented",
        )


class ExpectationTraceTest(unittest.TestCase):
    def test_expectation_trace_init(self):
        """
        testing the proper init of ExpectationTrace
        """
        expectation_id = "exp_id"
        source_id = "source_id"
        alert_name = "alert name"
        alert_link = "http://alert.link"
        date = "this is a date"

        expectation_trace = module.ExpectationTrace(
            inject_expectation_trace_expectation=expectation_id,
            inject_expectation_trace_source_id=source_id,
            inject_expectation_trace_alert_name=alert_name,
            inject_expectation_trace_alert_link=alert_link,
            inject_expectation_trace_date=date,
        )

        self.assertEqual(
            expectation_id, expectation_trace.inject_expectation_trace_expectation
        )
        self.assertEqual(
            source_id, expectation_trace.inject_expectation_trace_source_id
        )
        self.assertEqual(
            alert_name, expectation_trace.inject_expectation_trace_alert_name
        )
        self.assertEqual(
            alert_link, expectation_trace.inject_expectation_trace_alert_link
        )
        self.assertEqual(date, expectation_trace.inject_expectation_trace_date)

    def test_expectation_trace_to_api_dict(self):
        """ """
        expectation_id = "exp_id"
        source_id = "source_id"
        alert_name = "alert name"
        alert_link = "http://alert.link"
        date = "this is a date"
        expectation_trace = module.ExpectationTrace(
            inject_expectation_trace_expectation=expectation_id,
            inject_expectation_trace_source_id=source_id,
            inject_expectation_trace_alert_name=alert_name,
            inject_expectation_trace_alert_link=alert_link,
            inject_expectation_trace_date=date,
        )

        api_dict = expectation_trace.to_api_dict()

        self.assertEqual(
            api_dict["inject_expectation_trace_expectation"], expectation_id
        )
        self.assertEqual(api_dict["inject_expectation_trace_source_id"], source_id)
        self.assertEqual(api_dict["inject_expectation_trace_alert_name"], alert_name)
        self.assertEqual(api_dict["inject_expectation_trace_alert_link"], alert_link)
        self.assertEqual(api_dict["inject_expectation_trace_date"], date)

    def test_expectation_trace_from_result(self):
        """ """
        expectation_id = "id"
        is_valid = False
        expectation = MagicMock()
        _name = "my name is"
        _url = "http://alert.link"
        matched_alerts = [{"alert_name": _name, "alert_link": _url}]
        error_message = "this is an error"
        processing_time = 12.34
        expectation_result = module.ExpectationResult(
            expectation_id=expectation_id,
            is_valid=is_valid,
            expectation=expectation,
            matched_alerts=matched_alerts,
            error_message=error_message,
            processing_time=processing_time,
        )
        collector_id = "collector_id"
        collector_name = "collector name"

        expectation_trace = module.ExpectationTrace.from_result(
            expectation_result, collector_id, collector_name
        )

        self.assertEqual(
            expectation_trace.inject_expectation_trace_expectation,
            expectation_result.expectation_id,
        )
        self.assertEqual(
            expectation_trace.inject_expectation_trace_source_id, collector_id
        )
        self.assertEqual(expectation_trace.inject_expectation_trace_alert_name, _name)
        self.assertEqual(expectation_trace.inject_expectation_trace_alert_link, _url)
        self.assertEqual(expectation_trace.inject_expectation_trace_date, ANY)


class ExpectationSummaryTest(unittest.TestCase):
    def test_expectation_summary_minimal_init(self):
        """
        testing the proper init of ExpectationSummary with only required parameters
        """

        summary = module.ExpectationSummary()

        self.assertEqual(0, summary.received)
        self.assertEqual(0, summary.supported)
        self.assertEqual(0, summary.unsupported)
        self.assertEqual(0, summary.processed)
        self.assertEqual(0, summary.unprocessed)
        self.assertEqual(0, summary.valid)
        self.assertEqual(0, summary.invalid)
        self.assertEqual(0, summary.total_skipped)

    def test_expectation_summary_full_init(self):
        """
        testing the proper init of ExpectationSummary with all parameters
        """
        received = 100
        supported = 75
        processed = 40
        valid = 35

        summary = module.ExpectationSummary(
            received=received, supported=supported, processed=processed, valid=valid
        )

        self.assertEqual(100, summary.received)
        self.assertEqual(75, summary.supported)
        self.assertEqual(25, summary.unsupported)
        self.assertEqual(40, summary.processed)
        self.assertEqual(35, summary.unprocessed)
        self.assertEqual(35, summary.valid)
        self.assertEqual(5, summary.invalid)
        self.assertEqual(60, summary.total_skipped)

    def test_expectation_summary_str(self):
        """
        testing the formatting of ExpectationSummary into str
        """
        received = 100
        supported = 75
        processed = 40
        valid = 35

        summary = module.ExpectationSummary(
            received=received, supported=supported, processed=processed, valid=valid
        )

        self.assertEqual(
            str(summary),
            "100 expectations received, 75 expectations supported (25 unsupported), 40 expectations processed (35 unprocessed), 35 valid expectations (5 invalid)",
        )
