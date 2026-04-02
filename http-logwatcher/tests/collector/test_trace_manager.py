import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.collector.trace_manager as module


class TraceManagerTest(unittest.TestCase):
    def test_trace_manager_minimal_init(self):
        """
        testing the minimal init of the TraceManager object (only required parameters)
        debug logs should indicate the lack of trace service
        """
        oaev_api = MagicMock()
        collector_id = sentinel.collector_id

        with self.assertLogs(level="DEBUG") as log:
            trace_manager = module.TraceManager(
                oaev_api=oaev_api,
                collector_id=collector_id,
                trace_service=None,
            )

        self.assertIs(
            trace_manager.oaev_api,
            oaev_api,
        )
        self.assertIs(
            trace_manager.collector_id,
            sentinel.collector_id,
        )
        self.assertIsNone(
            trace_manager.trace_service,
        )

        self.assertIn("traces will be skipped", log.output[-1])

    def test_trace_manager_full_init(self):
        """
        testing the full init of the TraceManager object (all parameters available)
        debug logs should indicate the availability of the trace service
        """
        oaev_api = MagicMock()
        collector_id = sentinel.collector_id
        trace_service = MagicMock()

        with self.assertLogs(level="DEBUG") as log:
            trace_manager = module.TraceManager(
                oaev_api=oaev_api,
                collector_id=collector_id,
                trace_service=trace_service,
            )

        self.assertIs(
            trace_manager.oaev_api,
            oaev_api,
        )
        self.assertIs(
            trace_manager.collector_id,
            sentinel.collector_id,
        )
        self.assertIs(
            trace_manager.trace_service,
            trace_service,
        )

        self.assertIn("Trace service available", log.output[-1])

    @patch.object(module.TraceManager, "_submit_traces")
    def test_create_and_submit_traces(self, m_submit_traces):
        """
        testing the link between create_and_submit_traces, create_traces_from_results
        and submit_traces in the TraceManager object
        """
        oaev_api = MagicMock()
        collector_id = sentinel.collector_id
        trace_service = MagicMock()

        trace_manager = module.TraceManager(
            oaev_api=oaev_api,
            collector_id=collector_id,
            trace_service=trace_service,
        )

        expectation_result_0 = MagicMock()
        expectation_result_1 = MagicMock()
        results = [expectation_result_0, expectation_result_1]
        traces = MagicMock()
        trace_service.create_traces_from_results.return_value = traces

        trace_manager.create_and_submit_traces(results)

        trace_service.create_traces_from_results.assert_called_with(
            results,
            collector_id,
        )
        m_submit_traces.assert_called_with(traces)
