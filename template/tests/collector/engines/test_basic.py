import unittest
from unittest.mock import MagicMock, patch

import src.collector.engines.basic as module
from src.collector.models.source import SourceHandler


class TestBasicCollectorEngine(unittest.TestCase):
    def test_minimal_init(self):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        data_fetcher_model = MagicMock()
        signatures = MagicMock()
        source = MagicMock(spec=module.Source)
        source.data_fetcher_model = data_fetcher_model
        source.signatures = signatures
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        self.assertEqual(collector_engine.name, name)
        self.assertEqual(collector_engine.collector_id, collector_id)
        self.assertEqual(collector_engine.source, source)
        self.assertEqual(collector_engine.source_handler, source_handler)
        self.assertEqual(collector_engine.oaev_api, oaev_api)
        self.assertFalse(collector_engine.batching)
        self.assertFalse(collector_engine.configured)
        self.assertIsNotNone(collector_engine.logger)
        self.assertIsNotNone(collector_engine.current_summary)
        self.assertIsNone(collector_engine.oaev_detection_helper)
        self.assertIsNone(collector_engine.expectation_uploader)
        self.assertIsNone(collector_engine.trace_uploader)
        self.assertEqual(collector_engine.data_fetcher_model, source.data_fetcher_model)
        self.assertEqual(collector_engine.signatures, source.signatures)

    def test_full_init(self):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        data_fetcher_model = MagicMock()
        signatures = MagicMock()
        source = MagicMock(spec=module.Source)
        source.data_fetcher_model = data_fetcher_model
        source.signatures = signatures
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)
        batching = True

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
            batching=batching,
        )

        self.assertEqual(collector_engine.name, name)
        self.assertEqual(collector_engine.collector_id, collector_id)
        self.assertEqual(collector_engine.source, source)
        self.assertEqual(collector_engine.source_handler, source_handler)
        self.assertEqual(collector_engine.oaev_api, oaev_api)
        self.assertTrue(collector_engine.batching)
        self.assertFalse(collector_engine.configured)
        self.assertIsNotNone(collector_engine.logger)
        self.assertIsNotNone(collector_engine.current_summary)
        self.assertIsNone(collector_engine.oaev_detection_helper)
        self.assertIsNone(collector_engine.expectation_uploader)
        self.assertIsNone(collector_engine.trace_uploader)

    def test_wrong_source_init(self):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock()
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)

        with self.assertRaises(TypeError):
            module.BasicCollectorEngine(
                name=name,
                collector_id=collector_id,
                source=source,
                source_handler=source_handler,
                oaev_api=oaev_api,
            )

    def test_wrong_source_handler_init(self):
        """"""
        ...
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec_set=module.Source)
        source_handler = MagicMock()
        oaev_api = MagicMock(spec_set=module.OpenAEV)

        with self.assertRaises(TypeError):
            module.BasicCollectorEngine(
                name=name,
                collector_id=collector_id,
                source=source,
                source_handler=source_handler,
                oaev_api=oaev_api,
            )

    def test_wrong_oaev_api_init(self):
        """"""
        ...
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec_set=module.Source)
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock()

        with self.assertRaises(TypeError):
            module.BasicCollectorEngine(
                name=name,
                collector_id=collector_id,
                source=source,
                source_handler=source_handler,
                oaev_api=oaev_api,
            )

    @patch.object(module.BasicCollectorEngine, "_reset_summary")
    def test_configure_engine(self, m_reset_summary):
        """"""
        ...
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec=module.Source)
        source.signatures = [MagicMock()]
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)
        config = MagicMock()
        batching = True

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )
        collector_engine.configure_engine(config, batching)

        self.assertEqual(collector_engine.config, config)
        self.assertTrue(collector_engine.batching)
        self.assertIsNotNone(collector_engine.oaev_detection_helper)
        self.assertIsNotNone(collector_engine.expectation_uploader)
        self.assertIsNotNone(collector_engine.trace_uploader)
        self.assertTrue(collector_engine.configured)
        m_reset_summary.assert_called_once()

    def test_reset_summary(self):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec=module.Source)
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        collector_engine.current_summary.received = 50
        collector_engine.current_summary.supported = 30
        self.assertEqual(collector_engine.current_summary.received, 50)
        self.assertEqual(collector_engine.current_summary.supported, 30)
        collector_engine._reset_summary()
        self.assertEqual(collector_engine.current_summary.received, 0)
        self.assertEqual(collector_engine.current_summary.supported, 0)

    def test_filter_supported(self):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec=module.Source)
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)

        expectations = [
            MagicMock(spec=module.DetectionExpectation),
            MagicMock(spec=module.PreventionExpectation),
            "expectation",
            MagicMock(spec=module.PreventionExpectation),
        ]

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        supported_expectations = collector_engine._filter_supported(expectations)
        self.assertTrue(len(expectations) > len(supported_expectations))
        self.assertEqual(len(supported_expectations), 3)

    def test_fetch_expectations(self):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec=module.Source)
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec=module.OpenAEV)

        api_expectations = [
            MagicMock(spec=module.DetectionExpectation),
            MagicMock(spec=module.PreventionExpectation),
            "expectation",
            MagicMock(spec=module.PreventionExpectation),
        ]
        oaev_api.inject_expectation = MagicMock()
        oaev_api.inject_expectation.expectations_models_for_source.return_value = (
            api_expectations
        )

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        expectations = collector_engine._fetch_expectations()

        oaev_api.inject_expectation.expectations_models_for_source.assert_called_with(
            source_id=collector_id
        )
        self.assertEqual(expectations, list(reversed(api_expectations)))

    def test_fetch_expectations_api_failure(self):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec=module.Source)
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec=module.OpenAEV)

        oaev_api.inject_expectation = MagicMock()
        oaev_api.inject_expectation.expectations_models_for_source.side_effect = (
            Exception()
        )

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        expectations = collector_engine._fetch_expectations()

        self.assertEqual(expectations, [])
        oaev_api.inject_expectation.expectations_models_for_source.assert_called_with(
            source_id=collector_id
        )

    @patch.object(module.BasicCollectorEngine, "_filter_supported")
    @patch.object(module.BasicCollectorEngine, "_fetch_expectations")
    def test_fetch_and_filter_expectations(
        self, m_fetch_expectations, m_filter_supported
    ):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        source = MagicMock(spec_set=module.Source)
        source_handler = MagicMock(spec_set=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)
        fetched_expectations = [
            MagicMock,
        ]
        m_fetch_expectations.return_value = fetched_expectations
        supported_expectations = [
            MagicMock,
        ]
        m_filter_supported.return_value = supported_expectations

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        expectations = collector_engine.fetch_and_filter_expectations()

        m_fetch_expectations.assert_called_once()
        m_filter_supported.assert_called_with(fetched_expectations)
        self.assertEqual(expectations, supported_expectations)
        self.assertEqual(collector_engine.current_summary.received, 1)
        self.assertEqual(collector_engine.current_summary.supported, 1)

    @patch.object(module, "ExpectationResult")
    @patch.object(module.BasicCollectorEngine, "_reset_summary")
    def test_process_batch(
        self,
        m_reset_summary,
        m_expectation_result,
    ):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        signature_type = MagicMock(value="parent process name")
        data_fetcher_model = MagicMock()
        source = MagicMock(spec=module.Source)
        source.signatures = [
            signature_type,
        ]
        source.data_fetcher_model = data_fetcher_model
        source_handler = MagicMock(spec=SourceHandler)
        data_element = MagicMock()
        source_handler.get_source_data.return_value = [
            data_element,
        ]
        source_handler.match_expectation_and_sourcedata.side_effect = [
            [True, True],
            [False, False],
        ]
        oaev_api = MagicMock(spec_set=module.OpenAEV)

        expectation1 = MagicMock()
        expectation2 = MagicMock()
        batch = [expectation1, expectation2]
        result1 = MagicMock()
        result2 = MagicMock()
        m_expectation_result.side_effect = [result1, result2]

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        config = MagicMock()
        collector_engine.configure_engine(config)
        m_reset_summary.assert_called_once()

        batch_results = collector_engine._process_batch(batch)

        source_handler.get_source_data.assert_called_with(source.data_fetcher_model())
        self.assertEqual(source_handler.serialize_as_oaevdata._mock_call_count, 2)
        source_handler.serialize_as_oaevdata.assert_called_with(data_element)
        self.assertEqual(
            source_handler.get_expectation_signature_groups._mock_call_count, 2
        )
        source_handler.get_expectation_signature_groups.assert_any_call(
            source.signatures, expectation1
        )
        source_handler.get_expectation_signature_groups.assert_called_with(
            source.signatures, expectation2
        )
        source_handler.match_signature_groups_and_oaevdata.assert_any_call(
            source_handler.get_expectation_signature_groups.return_value,
            source_handler.serialize_as_oaevdata.return_value,
            collector_engine.oaev_detection_helper,
        )
        source_handler.serialize_as_tracedata.assert_called_with(data_element)
        self.assertEqual(
            source_handler.match_expectation_and_sourcedata._mock_call_count, 2
        )
        source_handler.match_expectation_and_sourcedata.assert_any_call(
            expectation1, data_element
        )
        source_handler.match_expectation_and_sourcedata.assert_called_with(
            expectation2, data_element
        )

        m_expectation_result.assert_any_call(
            expectation_id=str(expectation1.inject_expectation_id),
            is_valid=True,
            expectation=expectation1,
            matched_alerts=[source_handler.serialize_as_tracedata.return_value],
        )
        m_expectation_result.assert_any_call(
            expectation_id=str(expectation2.inject_expectation_id),
            is_valid=False,
            expectation=expectation2,
            matched_alerts=[source_handler.serialize_as_tracedata.return_value],
        )
        self.assertEqual(batch_results, [result1, result2])

    @patch.object(module, "TraceUploader")
    @patch.object(module, "ExpectationUploader")
    @patch.object(module.BasicCollectorEngine, "_process_batch")
    @patch.object(module.BasicCollectorEngine, "fetch_and_filter_expectations")
    @patch.object(module.BasicCollectorEngine, "_reset_summary")
    def test_run_engine(
        self,
        m_reset_summary,
        m_fetch_and_filter_expectations,
        m_process_batch,
        m_expectation_uploader,
        m_trace_uploader,
    ):
        """"""
        name = "my name is"
        collector_id = "1234abcd"
        signature_type = MagicMock(value="parent process name")
        data_fetcher_model = MagicMock()
        source = MagicMock(spec=module.Source)
        source.signatures = [
            signature_type,
        ]
        source.data_fetcher_model = data_fetcher_model
        source_handler = MagicMock(spec=SourceHandler)
        oaev_api = MagicMock(spec_set=module.OpenAEV)

        expectation1 = MagicMock()
        expectation2 = MagicMock()
        m_fetch_and_filter_expectations.return_value = [expectation1, expectation2]
        result1 = MagicMock()
        result2 = MagicMock()
        m_process_batch.return_value = [result1, result2]

        collector_engine = module.BasicCollectorEngine(
            name=name,
            collector_id=collector_id,
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        config = MagicMock()
        collector_engine.configure_engine(config)
        m_reset_summary.assert_called_once()

        collector_engine.run_engine()

        self.assertEqual(m_reset_summary._mock_call_count, 2)
        m_reset_summary.assert_any_call()

        m_fetch_and_filter_expectations.assert_called_once()
        m_process_batch.assert_called_once_with([expectation1, expectation2])
        m_expectation_uploader.return_value.upload_data.assert_any_call(
            [result1, result2]
        )
        m_trace_uploader.return_value.upload_data.assert_any_call([result1, result2])
