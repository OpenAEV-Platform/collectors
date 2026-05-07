import unittest
from unittest.mock import MagicMock, patch

import src.collector.internals.oaev_uploaders as module


class TestExpectationUploader(unittest.TestCase):
    def setUp(self):
        self.oaev_api = MagicMock()
        self.collector_id = "1234abcd"

        self.expectation_uploader = module.ExpectationUploader(
            oaev_api=self.oaev_api, collector_id=self.collector_id
        )

    def test_expectation_uploader_init(self):
        self.assertEqual(self.expectation_uploader.oaev_api, self.oaev_api)
        self.assertEqual(self.expectation_uploader.collector_id, self.collector_id)
        self.assertEqual(self.expectation_uploader.data_name, "expectation")

    def test_expectation_uploader_expectation_prepare_bulk_data(self):
        result1 = MagicMock()
        result1.expectation_id = "1"
        result1.expectation = MagicMock()
        result2 = MagicMock()
        result2.expectation_id = "2"
        result2.expectation = MagicMock()
        results = [result1, result2]

        bulked_data, skipped_count = (
            self.expectation_uploader.expectation_prepare_bulk_data(results)
        )

        self.assertEqual(
            bulked_data,
            {
                "1": {
                    "collector_id": self.expectation_uploader.collector_id,
                    "result": result1.to_result_text.return_value,
                    "is_success": result1.is_valid,
                },
                "2": {
                    "collector_id": self.expectation_uploader.collector_id,
                    "result": result2.to_result_text.return_value,
                    "is_success": result2.is_valid,
                },
            },
        )
        self.assertEqual(skipped_count, 0)

    def test_expectation_uploader_expectation_prepare_bulk_data_one_skipped(self):
        result1 = MagicMock()
        result1.expectation_id = "1"
        result1.expectation = None
        result2 = MagicMock()
        result2.expectation_id = "2"
        result2.expectation = MagicMock()
        results = [result1, result2]

        bulked_data, skipped_count = (
            self.expectation_uploader.expectation_prepare_bulk_data(results)
        )

        self.assertEqual(
            bulked_data,
            {
                "2": {
                    "collector_id": self.expectation_uploader.collector_id,
                    "result": result2.to_result_text.return_value,
                    "is_success": result2.is_valid,
                },
            },
        )
        self.assertEqual(skipped_count, 1)

    def test_expectation_uploader_expectation_bulk_upload(self):
        bulk_data = [MagicMock(), MagicMock(), MagicMock()]

        self.expectation_uploader.expectation_bulk_upload(bulk_data)

        self.oaev_api.inject_expectation.bulk_update.assert_called_once_with(
            inject_expectation_input_by=bulk_data
        )

    def test_expectation_uploader_expectation_unpack_bulk_data(self):
        bulk_data = {"one": 1, "two": 2, "three": 3}

        unpacked_data = self.expectation_uploader.expectation_unpack_bulk_data(
            bulk_data
        )

        self.assertEqual(list(unpacked_data), [("one", 1), ("two", 2), ("three", 3)])

    def test_expectation_uploader_expectation_individual_upload(self):
        expectation_id = 42
        expectation_data = MagicMock()

        self.expectation_uploader.expectation_individual_upload(
            expectation_id, expectation_data
        )

        self.oaev_api.inject_expectation.update.assert_called_once_with(
            inject_expectation_id=expectation_id,
            inject_expectation=expectation_data,
        )


class TestTraceUploader(unittest.TestCase):
    def setUp(self):
        self.oaev_api = MagicMock()
        self.collector_id = "1234abcd"
        self.collector_name = "my name is"

        self.trace_uploader = module.TraceUploader(
            oaev_api=self.oaev_api,
            collector_id=self.collector_id,
            collector_name=self.collector_name,
        )

    def test_trace_uploader_init(self):
        self.assertEqual(self.trace_uploader.oaev_api, self.oaev_api)
        self.assertEqual(self.trace_uploader.collector_id, self.collector_id)
        self.assertEqual(self.trace_uploader.collector_name, self.collector_name)
        self.assertEqual(self.trace_uploader.data_name, "trace")

    @patch.object(module, "ExpectationTrace")
    def test_trace_uploader_trace_prepare_bulk_data(self, m_expectationtrace):
        result1 = MagicMock()
        result1.is_valid = True
        result1.matched_alerts = [MagicMock()]
        result1.expectation_id = "1"
        result2 = MagicMock()
        result2.is_valid = True
        result2.matched_alerts = [MagicMock()]
        result2.expectation_id = "2"
        results = [result1, result2]
        exptrace1 = MagicMock()
        exptrace2 = MagicMock()
        m_expectationtrace.from_result.side_effect = [exptrace1, exptrace2]

        traces, skipped_count = self.trace_uploader.trace_prepare_bulk_data(results)

        m_expectationtrace.from_result.assert_any_call(
            result1,
            self.trace_uploader.collector_id,
            self.trace_uploader.collector_name,
        )
        m_expectationtrace.from_result.assert_any_call(
            result2,
            self.trace_uploader.collector_id,
            self.trace_uploader.collector_name,
        )
        self.assertEqual(traces, [exptrace1, exptrace2])
        self.assertEqual(skipped_count, 0)

    @patch.object(module, "ExpectationTrace")
    def test_trace_uploader_trace_prepare_bulk_data_one_skipped(
        self, m_expectationtrace
    ):
        result1 = MagicMock()
        result1.is_valid = True
        result1.matched_alerts = [MagicMock()]
        result1.expectation_id = "1"
        result2 = MagicMock()
        result2.is_valid = True
        result2.matched_alerts = [MagicMock()]
        result2.expectation_id = None
        results = [result1, result2]
        exptrace1 = MagicMock()
        m_expectationtrace.from_result.return_value = exptrace1

        traces, skipped_count = self.trace_uploader.trace_prepare_bulk_data(results)

        m_expectationtrace.from_result.assert_called_once_with(
            result1,
            self.trace_uploader.collector_id,
            self.trace_uploader.collector_name,
        )
        self.assertEqual(traces, [exptrace1])
        self.assertEqual(skipped_count, 1)

    def test_trace_uploader_trace_trace_bulk_upload(self):
        trace1 = MagicMock()
        trace2 = MagicMock()
        traces = [trace1, trace2]
        self.trace_uploader.trace_bulk_upload(traces)

        self.oaev_api.inject_expectation_trace.bulk_create.assert_called_once_with(
            payload={
                "expectation_traces": [
                    trace1.to_api_dict.return_value,
                    trace2.to_api_dict.return_value,
                ]
            }
        )

    def test_trace_uploader_trace_unpack_bulk_data(self):
        traces = ["one", "two", "three"]
        unpacked_data = self.trace_uploader.trace_unpack_bulk_data(traces)

        self.assertEqual(list(unpacked_data), [(1, "one"), (2, "two"), (3, "three")])

    def test_trace_uploader_trace_trace_individual_upload(self):
        trace = MagicMock()
        self.trace_uploader.trace_individual_upload(None, trace)

        self.oaev_api.inject_expectation_trace.create.assert_called_with(
            trace.to_api_dict.return_value
        )
