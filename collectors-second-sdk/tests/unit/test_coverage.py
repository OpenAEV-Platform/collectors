"""Coverage tests for BaseCollector, BasicCollectorEngine, and SourceHandler."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from collectors_second_sdk import (
    BaseCollector,
    BasicCollectorEngine,
    CollectorConfigError,
    CollectorEngineConfigError,
    CollectorProcessingError,
    CollectorSetupError,
    Source,
    SourceHandler,
)

# --- Helpers ---


class StubDataFetcher:
    def __init__(self, config: Any) -> None:
        self.config = config

    def fetch_data(self) -> list[Any]:
        return []


class StubSourceData:
    def to_oaev_data(self) -> Any:
        return MagicMock()

    def to_traces_data(self) -> Any:
        return MagicMock()

    def is_prevented(self) -> bool:
        return False

    def is_detected(self) -> bool:
        return True

    def __str__(self) -> str:
        return "stub"


def _make_source() -> Source:
    return Source(
        data_fetcher_model=StubDataFetcher,
        source_data_model=StubSourceData,
        signatures=[],
    )


# --- BaseCollector tests ---


class TestBaseCollectorLifecycle:
    def test_init_with_defaults(self) -> None:
        source = _make_source()
        collector = BaseCollector(name="test", source=source, oaev_api=MagicMock())
        assert collector.name == "test"
        assert isinstance(collector.source_handler, SourceHandler)

    def test_init_invalid_source_type(self) -> None:
        with pytest.raises(CollectorConfigError, match="not of type Source"):
            BaseCollector(name="test", source="not a source", oaev_api=MagicMock())  # type: ignore[arg-type]

    def test_init_invalid_engine_model(self) -> None:
        source = _make_source()

        class BadEngine:
            pass

        with pytest.raises(CollectorConfigError, match="CollectorEngineProtocol"):
            BaseCollector(name="test", source=source, engine_model=BadEngine, oaev_api=MagicMock())  # type: ignore[arg-type]

    def test_init_invalid_source_handler_model(self) -> None:
        source = _make_source()

        class BadHandler:
            pass

        with pytest.raises(CollectorConfigError, match="SourceHandlerProtocol"):
            BaseCollector(name="test", source=source, source_handler_model=BadHandler, oaev_api=MagicMock())  # type: ignore[arg-type]

    def test_engine_config_failure(self) -> None:
        source = _make_source()

        class FailEngine:
            def __init__(self, **kwargs: Any) -> None:
                raise RuntimeError("engine init fail")

            def configure_engine(self, config: Any, batching: bool = False) -> None: ...
            def run_engine(self) -> None: ...

        with pytest.raises(CollectorEngineConfigError, match="engine init fail"):
            BaseCollector(name="test", source=source, engine_model=FailEngine, oaev_api=MagicMock())

    def test_setup_configures_engine(self) -> None:
        source = _make_source()
        collector = BaseCollector(name="test", source=source, config=MagicMock(), oaev_api=MagicMock())
        collector._setup(batching=False)
        assert collector.engine.configured is True

    def test_setup_with_batching(self) -> None:
        source = _make_source()
        collector = BaseCollector(name="test", source=source, config=MagicMock(), oaev_api=MagicMock())
        collector._setup(batching=True)
        assert collector.engine.batching is True

    def test_setup_failure(self) -> None:
        source = _make_source()
        collector = BaseCollector(name="test", source=source, oaev_api=MagicMock())
        collector.engine.configure_engine = MagicMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("setup fail")
        )
        with pytest.raises(CollectorSetupError, match="setup fail"):
            collector._setup()


# --- BasicCollectorEngine tests ---


class TestBasicCollectorEngineProcessing:
    def _make_engine(self) -> BasicCollectorEngine:
        source = _make_source()
        handler = SourceHandler(config=MagicMock())
        api = MagicMock()
        return BasicCollectorEngine(
            name="test",
            collector_id="coll-001",
            source=source,
            source_handler=handler,
            oaev_api=api,
        )

    def test_configure_engine(self) -> None:
        engine = self._make_engine()
        assert engine.configured is False
        engine.configure_engine(config=MagicMock())
        assert engine.configured is True

    def test_data_fetcher_model_property(self) -> None:
        engine = self._make_engine()
        assert engine.data_fetcher_model is StubDataFetcher

    def test_signatures_property(self) -> None:
        engine = self._make_engine()
        assert engine.signatures == []

    def test_run_engine_not_configured_raises(self) -> None:
        engine = self._make_engine()
        with pytest.raises(CollectorEngineConfigError):
            engine.run_engine()

    def test_run_engine_no_expectations(self) -> None:
        engine = self._make_engine()
        engine.configure_engine(config=MagicMock())
        engine.oaev_api.inject_expectation.expectations_models_for_source.return_value = []
        engine.run_engine()
        assert engine.current_summary.received == 0

    def test_run_engine_with_expectations(self) -> None:
        engine = self._make_engine()
        engine.configure_engine(config=MagicMock())

        mock_exp = MagicMock()
        mock_exp.__class__.__name__ = "DetectionExpectation"
        mock_exp.inject_expectation_id = "exp-001"
        mock_exp.inject_expectation_signatures = []
        type(mock_exp).__name__ = "DetectionExpectation"

        engine.oaev_api.inject_expectation.expectations_models_for_source.return_value = [
            mock_exp
        ]

        engine.source_handler.get_source_data = MagicMock(return_value=[])  # type: ignore[method-assign]
        engine.run_engine()
        assert engine.current_summary.received == 1
        assert engine.current_summary.supported == 1

    def test_run_engine_api_failure(self) -> None:
        engine = self._make_engine()
        engine.configure_engine(config=MagicMock())
        engine.oaev_api.inject_expectation.expectations_models_for_source.side_effect = (
            RuntimeError("api fail")
        )
        # Should not raise — returns empty list on API error
        engine.run_engine()
        assert engine.current_summary.received == 0

    def test_filter_supported(self) -> None:
        engine = self._make_engine()
        det = MagicMock()
        type(det).__name__ = "DetectionExpectation"
        prev = MagicMock()
        type(prev).__name__ = "PreventionExpectation"
        other = MagicMock()
        type(other).__name__ = "OtherType"

        result = engine._filter_supported([det, prev, other])
        assert len(result) == 2

    def test_reset_summary(self) -> None:
        engine = self._make_engine()
        engine.current_summary.received = 99
        engine._reset_summary()
        assert engine.current_summary.received == 0

    def test_process_batch_data_fetch_error(self) -> None:
        engine = self._make_engine()
        engine.source_handler.get_source_data = MagicMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("fetch fail")
        )
        mock_exp = MagicMock()
        mock_exp.inject_expectation_id = "exp-001"
        results = engine._process_batch([mock_exp])
        assert len(results) == 1
        assert results[0].is_valid is False

    def test_process_batch_with_matching_data(self) -> None:
        engine = self._make_engine()

        mock_data = MagicMock()
        engine.source_handler.get_source_data = MagicMock(return_value=[mock_data])  # type: ignore[method-assign]
        engine.source_handler.serialize_as_oaevdata = MagicMock(return_value=MagicMock())  # type: ignore[method-assign]
        engine.source_handler.get_expectation_signature_groups = MagicMock(  # type: ignore[method-assign]
            return_value={}
        )
        engine.source_handler.match_signature_groups_and_oaevdata = MagicMock(  # type: ignore[method-assign]
            return_value=True
        )
        trace_mock = MagicMock()
        trace_mock.model_dump.return_value = {"alert_name": "test"}
        engine.source_handler.serialize_as_tracedata = MagicMock(  # type: ignore[method-assign]
            return_value=trace_mock
        )
        engine.source_handler.match_expectation_and_sourcedata = MagicMock(  # type: ignore[method-assign]
            return_value=(True, False)
        )

        mock_exp = MagicMock()
        mock_exp.inject_expectation_id = "exp-001"
        results = engine._process_batch([mock_exp])
        assert len(results) == 1
        assert results[0].is_valid is True
        assert len(results[0].matched_alerts) == 1

    def test_process_batch_per_expectation_error(self) -> None:
        engine = self._make_engine()
        engine.source_handler.get_source_data = MagicMock(return_value=[MagicMock()])  # type: ignore[method-assign]
        engine.source_handler.serialize_as_oaevdata = MagicMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("serialize fail")
        )

        mock_exp = MagicMock()
        mock_exp.inject_expectation_id = "exp-001"
        results = engine._process_batch([mock_exp])
        assert len(results) == 1
        assert results[0].is_valid is False

    def test_run_engine_processing_error_raises(self) -> None:
        engine = self._make_engine()
        engine.configure_engine(config=MagicMock())
        engine.fetch_and_filter_expectations = MagicMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("processing fail")
        )
        with pytest.raises(CollectorProcessingError, match="processing fail"):
            engine.run_engine()

    def test_run_engine_batched_mode(self) -> None:
        engine = self._make_engine()
        config = MagicMock()
        config.expectation_batch_size = 2
        engine.configure_engine(config=config, batching=True)

        mock_exps = []
        for i in range(3):
            exp = MagicMock()
            type(exp).__name__ = "DetectionExpectation"
            exp.inject_expectation_id = f"exp-{i}"
            mock_exps.append(exp)

        engine.oaev_api.inject_expectation.expectations_models_for_source.return_value = (
            mock_exps
        )
        engine.source_handler.get_source_data = MagicMock(return_value=[])  # type: ignore[method-assign]
        engine.run_engine()
        assert engine.current_summary.processed == 3


# --- SourceHandler tests ---


class TestSourceHandlerMethods:
    def test_get_source_data_delegates(self) -> None:
        handler = SourceHandler(config=MagicMock())
        fetcher = MagicMock()
        fetcher.fetch_data.return_value = ["item1", "item2"]
        result = handler.get_source_data(fetcher)
        assert result == ["item1", "item2"]

    def test_serialize_as_oaevdata(self) -> None:
        from collectors_second_sdk import OAEVData

        handler = SourceHandler(config=MagicMock())
        mock_data = MagicMock()
        oaev = OAEVData()
        mock_data.to_oaev_data.return_value = oaev
        result = handler.serialize_as_oaevdata(mock_data)
        assert result is oaev

    def test_serialize_as_tracedata(self) -> None:
        handler = SourceHandler(config=MagicMock())
        mock_data = MagicMock()
        trace = MagicMock()
        mock_data.to_traces_data.return_value = trace
        result = handler.serialize_as_tracedata(mock_data)
        assert result is trace

    def test_get_expectation_signature_groups(self) -> None:
        handler = SourceHandler(config=MagicMock())
        mock_sig = MagicMock()
        mock_sig.value = "process_name"

        mock_exp = MagicMock()
        sig_item = MagicMock()
        sig_item.type.value = "process_name"
        sig_item.value = "cmd.exe"
        mock_exp.inject_expectation_signatures = [sig_item]

        result = handler.get_expectation_signature_groups([mock_sig], mock_exp)
        assert "process_name" in result
        assert result["process_name"][0]["value"] == "cmd.exe"

    def test_get_expectation_signature_groups_skips_unsupported(self) -> None:
        handler = SourceHandler(config=MagicMock())
        mock_sig = MagicMock()
        mock_sig.value = "process_name"

        mock_exp = MagicMock()
        sig_item = MagicMock()
        sig_item.type.value = "unsupported_type"
        sig_item.value = "foo"
        mock_exp.inject_expectation_signatures = [sig_item]

        result = handler.get_expectation_signature_groups([mock_sig], mock_exp)
        assert result == {}

    def test_get_expectation_signature_groups_skips_end_date(self) -> None:
        handler = SourceHandler(config=MagicMock())
        mock_sig = MagicMock()
        mock_sig.value = "end_date"

        mock_exp = MagicMock()
        sig_item = MagicMock()
        sig_item.type.value = "end_date"
        sig_item.value = "2024-01-01"
        mock_exp.inject_expectation_signatures = [sig_item]

        result = handler.get_expectation_signature_groups([mock_sig], mock_exp)
        assert result == {}

    def test_match_signature_groups_and_oaevdata_true(self) -> None:
        handler = SourceHandler(config=MagicMock())
        oaev_data = MagicMock()
        oaev_data.process_name = "cmd.exe"
        helper = MagicMock()
        helper.match_alert_elements.return_value = True

        result = handler.match_signature_groups_and_oaevdata(
            {"process_name": [{"type": "process_name", "value": "cmd.exe"}]},
            oaev_data,
            helper,
        )
        assert result is True

    def test_match_signature_groups_and_oaevdata_no_data(self) -> None:
        handler = SourceHandler(config=MagicMock())
        result = handler.match_signature_groups_and_oaevdata({}, None, MagicMock())
        assert result is False

    def test_match_signature_groups_missing_attr(self) -> None:
        handler = SourceHandler(config=MagicMock())
        oaev_data = MagicMock(spec=[])  # no attributes
        result = handler.match_signature_groups_and_oaevdata(
            {"process_name": [{"type": "process_name", "value": "cmd.exe"}]},
            oaev_data,
            MagicMock(),
        )
        assert result is False

    def test_match_signature_groups_no_match(self) -> None:
        handler = SourceHandler(config=MagicMock())
        oaev_data = MagicMock()
        oaev_data.process_name = "cmd.exe"
        helper = MagicMock()
        helper.match_alert_elements.return_value = False

        result = handler.match_signature_groups_and_oaevdata(
            {"process_name": [{"type": "process_name", "value": "cmd.exe"}]},
            oaev_data,
            helper,
        )
        assert result is False

    def test_match_expectation_detection(self) -> None:
        handler = SourceHandler(config=MagicMock())
        exp = MagicMock()
        type(exp).__name__ = "DetectionExpectation"
        data = MagicMock()
        data.is_detected.return_value = True
        matchflag, breakflag = handler.match_expectation_and_sourcedata(exp, data)
        assert matchflag is True
        assert breakflag is False

    def test_match_expectation_detection_no_match(self) -> None:
        handler = SourceHandler(config=MagicMock())
        exp = MagicMock()
        type(exp).__name__ = "DetectionExpectation"
        data = MagicMock()
        data.is_detected.return_value = False
        matchflag, breakflag = handler.match_expectation_and_sourcedata(exp, data)
        assert matchflag is False
        assert breakflag is False

    def test_match_expectation_prevention(self) -> None:
        handler = SourceHandler(config=MagicMock())
        exp = MagicMock()
        type(exp).__name__ = "PreventionExpectation"
        data = MagicMock()
        data.is_prevented.return_value = True
        matchflag, breakflag = handler.match_expectation_and_sourcedata(exp, data)
        assert matchflag is True
        assert breakflag is True

    def test_match_expectation_prevention_no_match(self) -> None:
        handler = SourceHandler(config=MagicMock())
        exp = MagicMock()
        type(exp).__name__ = "PreventionExpectation"
        data = MagicMock()
        data.is_prevented.return_value = False
        matchflag, breakflag = handler.match_expectation_and_sourcedata(exp, data)
        assert matchflag is False
        assert breakflag is False
