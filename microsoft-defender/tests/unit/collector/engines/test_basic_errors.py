"""
collectors#723: a failed alert fetch or a processing error is never written
to OpenAEV as "Not Detected" / "Not Prevented".
"""

import unittest
from unittest.mock import MagicMock, patch

import requests
import src.collector.engines.basic as module
import src.collector.internals.oaev_uploaders as uploaders_module
from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
)
from src.collector.models.expectations import ExpectationResult
from src.collector.models.source import SourceHandler


def _detection_expectation(expectation_id: str) -> MagicMock:
    expectation = MagicMock(spec=DetectionExpectation)
    expectation.inject_expectation_id = expectation_id
    return expectation


class TestProcessBatchErrors(unittest.TestCase):
    def setUp(self):
        source = MagicMock(spec=module.Source)
        source.signatures = [MagicMock(value="parent process name")]
        source.data_fetcher_model = MagicMock()
        self.source_handler = MagicMock(spec=SourceHandler)
        self.source_handler.config = MagicMock()
        self.oaev_api = MagicMock(spec_set=module.OpenAEV)
        self.engine = module.BasicCollectorEngine(
            name="defender",
            collector_id="1234abcd",
            source=source,
            source_handler=self.source_handler,
            oaev_api=self.oaev_api,
        )
        self.engine.configure_engine(MagicMock())
        self.batch = [_detection_expectation("e1"), _detection_expectation("e2")]

    def _run_cycle(self, batch):
        """process the batch, then hand its results to the real uploader"""
        results = self.engine._process_batch(batch)
        bulk_data, _ = self.engine.expectation_uploader.expectation_prepare_bulk_data(
            results
        )
        return results, bulk_data

    @patch.object(module, "time_window_over", return_value=False)
    @patch.object(module, "detect_correct_date", return_value=True)
    def test_fetch_error_inside_window_produces_nothing(self, _date, _window):
        self.source_handler.get_source_data.side_effect = (
            requests.exceptions.ConnectionError("graph unreachable")
        )

        results, bulk_data = self._run_cycle(self.batch)

        self.assertEqual(results, [])
        self.assertEqual(bulk_data, {})

    @patch.object(module, "time_window_over", return_value=True)
    @patch.object(module, "detect_correct_date", return_value=True)
    def test_fetch_error_window_over_never_writes_not_detected(self, _date, _window):
        self.source_handler.get_source_data.side_effect = (
            requests.exceptions.ConnectionError("graph unreachable")
        )

        results, bulk_data = self._run_cycle(self.batch)

        self.assertFalse(
            [
                r
                for r in results
                if not r.is_valid and r.to_result_text() == "Not Detected"
            ]
        )
        self.assertEqual(bulk_data, {})

    @patch.object(module, "time_window_over", return_value=True)
    @patch.object(module, "detect_correct_date", return_value=True)
    def test_per_expectation_error_is_not_uploaded_as_a_miss(self, _date, _window):
        self.source_handler.get_source_data.return_value = [MagicMock()]
        self.source_handler.match_signature_groups_and_alert_data.side_effect = (
            RuntimeError("malformed alert")
        )

        results, bulk_data = self._run_cycle(self.batch)

        self.assertEqual(results, [])
        self.assertEqual(bulk_data, {})

    @patch.object(module, "time_window_over", return_value=True)
    @patch.object(module, "detect_correct_date", return_value=True)
    def test_genuine_no_match_past_window_is_still_not_detected(self, _date, _window):
        self.source_handler.get_source_data.return_value = [MagicMock()]
        self.source_handler.match_signature_groups_and_alert_data.return_value = False

        results, bulk_data = self._run_cycle(self.batch)

        self.assertEqual(len(results), 2)
        for expectation_id in ("e1", "e2"):
            self.assertEqual(bulk_data[expectation_id]["result"], "Not Detected")
            self.assertFalse(bulk_data[expectation_id]["is_success"])


class TestExpectationUploaderErrorGuard(unittest.TestCase):
    def test_result_with_error_message_is_never_bulked(self):
        uploader = uploaders_module.ExpectationUploader(
            oaev_api=MagicMock(), collector_id="1234abcd"
        )
        errored = ExpectationResult.from_error(
            RuntimeError("graph 503"), _detection_expectation("e1")
        )
        genuine = ExpectationResult(
            expectation_id="e2",
            is_valid=False,
            expectation=_detection_expectation("e2"),
        )

        bulk_data, skipped_count = uploader.expectation_prepare_bulk_data(
            [errored, genuine]
        )

        self.assertNotIn("e1", bulk_data)
        self.assertEqual(bulk_data["e2"]["result"], "Not Detected")
        self.assertEqual(skipped_count, 1)


if __name__ == "__main__":
    unittest.main()
