"""Tests for the signature names collectors read in the pending expectations.

Feature: Pending expectations with signature names collectors do not know
  The platform stores a signature under the name it arrives with: a legacy name
  (start_time, target_ipv4…) or a custom one an injector added. One such signature
  must not make a collector refuse the whole pending feed: a legacy name reads as its
  signature type, and a signature of an unknown type is dropped, with a warning, from
  its expectation only.
"""

import logging
from typing import Any
from uuid import uuid4

import collectors_sdk
import pytest


class _ExpectationApi:
    """Stands for the OpenAEV client's inject expectation manager."""

    def __init__(self, expectations: list[dict[str, Any]]) -> None:
        self.expectations = expectations

    def expectations_assets_for_source(self, source_id: str, **_: Any) -> list:
        return [dict(expectation) for expectation in self.expectations]

    def update(self, *_: Any, **__: Any) -> None:
        pass


def _expectation(kind: str, *signatures: tuple[str, str]) -> dict[str, Any]:
    return {
        "inject_expectation_id": str(uuid4()),
        "inject_expectation_type": kind,
        "inject_expectation_signatures": [
            {"type": name, "value": value} for name, value in signatures
        ],
    }


def _given_feed(*expectations: dict[str, Any]) -> _ExpectationApi:
    """Given the pending expectations <expectations>"""
    return _ExpectationApi(list(expectations))


def _when_loading_the_models(
    api: _ExpectationApi, caplog: pytest.LogCaptureFixture
) -> Any:
    """When the collector loads its expectation models"""
    with caplog.at_level(logging.WARNING):
        try:
            return collectors_sdk.expectations_models_for_source(
                api, source_id="c0ffee-collector"
            )
        except Exception as error:  # noqa: BLE001
            return error


def _then_models_are(models: Any, *kinds: type) -> None:
    """Then the models are exactly <kinds>, in order"""
    assert isinstance(models, list), f"Expected the feed to load, got {models!r}"
    assert [type(m) for m in models] == list(kinds)


def _then_signatures_of(models: Any, index: int, *expected: tuple[str, str]) -> None:
    """Then model <index> keeps exactly the signatures "<type> <value>" """
    found = [
        (s.type.value, s.value) for s in models[index].inject_expectation_signatures
    ]
    assert found == list(expected)


def _then_warning_names(caplog: pytest.LogCaptureFixture, name: str) -> None:
    """Then a warning names "<name>" """
    assert name in caplog.text, f"Expected a warning naming {name!r}: {caplog.text!r}"


def test_a_signature_of_unknown_type_is_dropped_not_the_feed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """It drops a signature of unknown type and keeps loading the whole feed.

    Scenario: A signature of unknown type is dropped, not the feed
      Given the pending expectations:
        | type       | signatures                                                 |
        | DETECTION  | ports_discovered "22", parent_process_name "oaev-implant-x" |
        | PREVENTION | target_ipv4_address "10.0.0.5"                             |
      When the collector loads its expectation models
      Then the models are exactly a detection and a prevention, in order
      And model 0 keeps exactly the signatures "parent_process_name oaev-implant-x"
      And model 1 keeps exactly the signatures "target_ipv4_address 10.0.0.5"
    """
    api = _given_feed(
        _expectation(
            "DETECTION",
            ("ports_discovered", "22"),
            ("parent_process_name", "oaev-implant-x"),
        ),
        _expectation("PREVENTION", ("target_ipv4_address", "10.0.0.5")),
    )
    models = _when_loading_the_models(api, caplog)
    _then_models_are(
        models,
        collectors_sdk.DetectionExpectation,
        collectors_sdk.PreventionExpectation,
    )
    _then_signatures_of(models, 0, ("parent_process_name", "oaev-implant-x"))
    _then_signatures_of(models, 1, ("target_ipv4_address", "10.0.0.5"))


def test_a_dropped_signature_is_named_in_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """It says which signature type it dropped.

    Scenario: A dropped signature is named in a warning
      Given the pending expectations:
        | type      | signatures            |
        | DETECTION | ports_discovered "22" |
      When the collector loads its expectation models
      Then a warning names "ports_discovered"
    """
    api = _given_feed(_expectation("DETECTION", ("ports_discovered", "22")))
    _when_loading_the_models(api, caplog)
    _then_warning_names(caplog, "ports_discovered")


def test_a_legacy_name_reads_as_its_signature_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """It reads a signature stored under a legacy name as its signature type.

    Scenario: A legacy name reads as its signature type
      Given the pending expectations:
        | type      | signatures                                         |
        | DETECTION | start_time "2026-11-05T10:00:00Z", target_ipv4 "10.0.0.5" |
      When the collector loads its expectation models
      Then the models are exactly a detection
      And model 0 keeps exactly the signatures "start_date 2026-11-05T10:00:00Z" and "target_ipv4_address 10.0.0.5"
    """
    api = _given_feed(
        _expectation(
            "DETECTION",
            ("start_time", "2026-11-05T10:00:00Z"),
            ("target_ipv4", "10.0.0.5"),
        )
    )
    models = _when_loading_the_models(api, caplog)
    _then_models_are(models, collectors_sdk.DetectionExpectation)
    _then_signatures_of(
        models,
        0,
        ("start_date", "2026-11-05T10:00:00Z"),
        ("target_ipv4_address", "10.0.0.5"),
    )
