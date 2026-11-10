"""Expectation models built by collectors-sdk from the platform expectation data."""

from typing import Any
from uuid import uuid4

import collectors_sdk


class _FakeExpectationApi:
    """Stands for the OpenAEV client's inject expectation manager."""

    def __init__(self, expectations: list[dict[str, Any]]) -> None:
        self.expectations = expectations
        self.fetches: list[tuple[str, dict[str, Any]]] = []
        self.updates: list[tuple[Any, dict[str, Any]]] = []

    def expectations_assets_for_source(
        self, source_id: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        self.fetches.append((source_id, kwargs))
        return [dict(expectation) for expectation in self.expectations]

    def update(
        self, inject_expectation_id: Any, inject_expectation: dict[str, Any], **kwargs
    ) -> None:
        self.updates.append((inject_expectation_id, inject_expectation))


def _given_expectation(expectation_type: str) -> dict[str, Any]:
    return {
        "inject_expectation_id": str(uuid4()),
        "inject_expectation_type": expectation_type,
        "inject_expectation_signatures": [],
    }


def _given_api(*expectation_types: str) -> _FakeExpectationApi:
    return _FakeExpectationApi([_given_expectation(t) for t in expectation_types])


def _when_load_models(api: _FakeExpectationApi, **kwargs: Any) -> list[Any]:
    return collectors_sdk.expectations_models_for_source(api, "collector-1", **kwargs)


def _then_model_types_are(models: list[Any], *expected: type) -> None:
    assert [type(model) for model in models] == list(expected)


def test_detection_and_prevention_data_become_their_models() -> None:
    """It builds a DetectionExpectation or PreventionExpectation per type."""
    api = _given_api("DETECTION", "PREVENTION")
    models = _when_load_models(api)
    _then_model_types_are(
        models,
        collectors_sdk.DetectionExpectation,
        collectors_sdk.PreventionExpectation,
    )


def test_unknown_expectation_type_becomes_a_prevention_model() -> None:
    """It keeps the legacy fallback: any other type becomes a PreventionExpectation."""
    api = _given_api("MANUAL")
    models = _when_load_models(api)
    _then_model_types_are(models, collectors_sdk.PreventionExpectation)


def test_fetch_passes_the_source_and_extra_arguments() -> None:
    """It asks the API for the expectations of the source, with the extra arguments."""
    api = _given_api()
    _when_load_models(api, expiration_time=42)
    assert api.fetches == [("collector-1", {"expiration_time": 42})]


def test_models_report_their_outcome_through_the_same_api() -> None:
    """It wires each model to the API it came from, so update() reaches it."""
    api = _given_api("DETECTION")
    (model,) = _when_load_models(api)
    model.update(success=True, sender_id="collector-1", metadata={})
    assert api.updates == [
        (
            model.inject_expectation_id,
            {
                "collector_id": "collector-1",
                "result": "Detected",
                "is_success": True,
                "metadata": {},
            },
        )
    ]


def test_any_object_with_the_two_methods_is_an_expectation_api() -> None:
    """It accepts any object implementing ExpectationApiProtocol."""
    api = _given_api()
    assert isinstance(api, collectors_sdk.ExpectationApiProtocol)
