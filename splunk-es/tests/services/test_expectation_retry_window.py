"""Detection verdicts tolerate late risk-index ingestion (retry window).

Behavior contract (Gherkin), ported from the Microsoft Defender collector's
latency handling (#610, "handle latency in alert availability", and #651,
"smarter use of start_date"):

Feature: Detection verdicts wait for late risk-index ingestion
  As a purple-team operator
  I want an unmatched detection expectation to stay pending until its
  retry window has elapsed
  So that risk events indexed late are not reported as Not Detected

  Background:
    Given the collector's retry window is 20 minutes

  Scenario: A risk event indexed after the first run is still detected
    Given a detection expectation whose end date was 7 minutes ago
    And the risk index only holds risk events of other expectations
    When the collector runs
    And the expectation's risk event is then indexed
    And the collector runs again
    Then the expectation is resolved Detected without ever being Not Detected

  Scenario: An unmatched expectation stays pending while its window is open
    Given a detection expectation whose end date was 7 minutes ago
    And the risk index only holds risk events of other expectations
    When the collector runs
    Then no verdict is written for the expectation

  Scenario: An expectation with no risk event at all stays pending while its window is open
    Given a detection expectation whose end date was 7 minutes ago
    And the risk index holds no risk event
    When the collector runs
    Then no verdict is written for the expectation

  Scenario: A matching expectation is detected at once, inside its window
    Given a detection expectation whose end date was 7 minutes ago
    And the risk index holds its risk event
    When the collector runs
    Then the expectation is resolved Detected

  Scenario Outline: The window is anchored on the end date, or 1.5x on the start date
    Given a detection expectation carrying <dates> from <age> ago
    And the risk index only holds risk events of other expectations
    When the collector runs
    Then the expectation's verdict is <verdict>

    Examples:
      | dates                          | age | verdict      |
      | an end date                    | 19m | pending      |
      | an end date                    | 21m | Not Detected |
      | only a start date              | 29m | pending      |
      | only a start date              | 31m | Not Detected |

  # ---- Constraints identified ----

  Scenario: An expectation with neither start nor end date is not evaluated
    Given a detection expectation with neither a start date nor an end date
    And a dated detection expectation whose risk event is indexed
    When the collector runs
    Then only the dated expectation is resolved
    And Splunk ES is searched only for the dated expectation

  Scenario: A malformed date counts as no date
    Given a detection expectation whose only date signature is malformed
    When the collector runs
    Then no verdict is written for the expectation

  Scenario: An end date with a timezone offset is compared in UTC
    Given a detection expectation whose end date, written as +02:00 local
      time, was 21 minutes ago
    And the risk index only holds risk events of other expectations
    When the collector runs
    Then the expectation is resolved Not Detected

  Scenario: A Splunk ES failure is still reported at once
    Given a detection expectation whose end date was 7 minutes ago
    And the Splunk ES search fails
    When the collector runs
    Then the expectation is resolved Not Detected

  Scenario: The retry window defaults to 20 minutes and is configurable
    Given SPLUNKES_RETRY_WINDOW is unset, or set to PT30M
    When the collector configuration is loaded
    Then the retry window is 20 minutes, or 30 minutes
    (see tests/test_splunkes_configs.py)

  Scenario: A prevention expectation is still answered at once
    Given a prevention expectation whose end date was 7 minutes ago
    When the collector runs
    Then the expectation is resolved Not Prevented

"""

from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
import src.services.expectation_service as module
from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]
from src.collector.models import ExpectationResult
from src.services.exception import SplunkESAPIError
from src.services.models import SplunkESAlert, SplunkESResponse

RETRY_WINDOW = timedelta(minutes=20)

IMPLANT = (
    "oaev-implant-b3e00a6f-d304-4f0d-bf7c-1458730aaa28-"
    "agent-700c4d5d-58e1-4bb2-8e83-c9273aeb19af"
)
OTHER_IMPLANT = (
    "oaev-implant-8eeadfc0-4010-4e1f-b2b4-2688e78a9ead-"
    "agent-700c4d5d-58e1-4bb2-8e83-c9273aeb19af"
)

PENDING = "pending"
DETECTED = "Detected"
NOT_DETECTED = "Not Detected"


# ---- Background ---------------------------------------------------------


@pytest.fixture()
def service() -> Any:
    """Given the collector's retry window is 20 minutes."""
    config = MagicMock()
    config.splunk_es.time_window = timedelta(hours=1)
    config.splunk_es.max_retry = 0
    config.splunk_es.offset = timedelta(seconds=0)
    config.splunk_es.retry_window = RETRY_WINDOW
    with patch.object(module, "SplunkESClientAPI"):
        yield module.SplunkESExpectationService(config)


# ---- Given --------------------------------------------------------------


def _iso(moment: datetime, utc_offset: timedelta = timedelta(0)) -> str:
    return moment.astimezone(timezone(utc_offset)).isoformat()


def _given_detection_expectation(
    end_date_age: timedelta | None = None,
    start_date_age: timedelta | None = None,
    raw_dates: dict[SignatureTypes, str] | None = None,
    expectation_cls: type = DetectionExpectation,
) -> Any:
    now = datetime.now(UTC)
    signatures = [
        {"type": SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME, "value": IMPLANT},
        {"type": SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS, "value": "10.186.33.6"},
    ]
    if start_date_age is not None:
        signatures.append(
            {
                "type": SignatureTypes.SIG_TYPE_START_DATE,
                "value": _iso(now - start_date_age),
            }
        )
    if end_date_age is not None:
        signatures.append(
            {
                "type": SignatureTypes.SIG_TYPE_END_DATE,
                "value": _iso(now - end_date_age),
            }
        )
    for sig_type, value in (raw_dates or {}).items():
        signatures.append({"type": sig_type, "value": value})
    return expectation_cls(
        inject_expectation_id=uuid4(),
        inject_expectation_signatures=signatures,
        api_client=None,
    )


def _risk_event(implant: str) -> SplunkESAlert:
    row = {
        "_time": "2026-11-10T22:21:11Z",
        "src": "10.186.33.6",
        "_raw": f"risk_object=G027WIDA100000C parent_process_name={implant}.exe",
    }
    return SplunkESResponse.from_raw_response({"results": [row]}).results[0]


def _given_risk_index_holds(service: Any, *runs: list[SplunkESAlert]) -> None:
    """Each argument is what the risk index returns on one successive run."""
    service.client_api.fetch_with_retry.side_effect = list(runs)


def _other_expectations_events() -> list[SplunkESAlert]:
    return [_risk_event(OTHER_IMPLANT) for _ in range(11)]


def _expectation_own_event() -> list[SplunkESAlert]:
    return [*_other_expectations_events(), _risk_event(IMPLANT)]


# ---- When ---------------------------------------------------------------


def _when_collector_runs(service: Any, *expectations: Any) -> list[ExpectationResult]:
    return service.handle_batch_expectations(list(expectations), MagicMock())


# ---- Then ---------------------------------------------------------------


def _verdict_of(results: list[ExpectationResult], expectation: Any) -> str:
    expectation_id = str(expectation.inject_expectation_id)
    verdicts = [r for r in results if r.expectation_id == expectation_id]
    assert len(verdicts) <= 1, f"several verdicts for one expectation: {verdicts}"
    if not verdicts:
        return PENDING
    if isinstance(expectation, PreventionExpectation):
        return "Prevented" if verdicts[0].is_valid else "Not Prevented"
    return DETECTED if verdicts[0].is_valid else NOT_DETECTED


def _then_verdict_is(
    results: list[ExpectationResult], expectation: Any, expected: str
) -> None:
    assert _verdict_of(results, expectation) == expected


# ---- Scenarios ----------------------------------------------------------


def test_risk_event_indexed_after_first_run_is_still_detected(service):
    expectation = _given_detection_expectation(end_date_age=timedelta(minutes=7))
    _given_risk_index_holds(
        service, _other_expectations_events(), _expectation_own_event()
    )

    first_run = _when_collector_runs(service, expectation)
    second_run = _when_collector_runs(service, expectation)

    _then_verdict_is(first_run, expectation, PENDING)
    _then_verdict_is(second_run, expectation, DETECTED)


def test_unmatched_expectation_stays_pending_while_window_is_open(service):
    expectation = _given_detection_expectation(end_date_age=timedelta(minutes=7))
    _given_risk_index_holds(service, _other_expectations_events())

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, PENDING)


def test_expectation_without_any_risk_event_stays_pending_while_window_is_open(
    service,
):
    expectation = _given_detection_expectation(end_date_age=timedelta(minutes=7))
    _given_risk_index_holds(service, [])

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, PENDING)


def test_matching_expectation_is_detected_at_once_inside_its_window(service):
    expectation = _given_detection_expectation(end_date_age=timedelta(minutes=7))
    _given_risk_index_holds(service, _expectation_own_event())

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, DETECTED)


@pytest.mark.parametrize(
    ("dates", "verdict"),
    [
        ({"end_date_age": timedelta(minutes=19)}, PENDING),
        ({"end_date_age": timedelta(minutes=21)}, NOT_DETECTED),
        ({"start_date_age": timedelta(minutes=29)}, PENDING),
        ({"start_date_age": timedelta(minutes=31)}, NOT_DETECTED),
    ],
    ids=[
        "end-date-19m-pending",
        "end-date-21m-not-detected",
        "start-date-only-29m-pending",
        "start-date-only-31m-not-detected",
    ],
)
def test_window_is_anchored_on_end_date_or_1_5x_on_start_date(service, dates, verdict):
    expectation = _given_detection_expectation(**dates)
    _given_risk_index_holds(service, _other_expectations_events())

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, verdict)


# ---- Constraints identified ---------------------------------------------


def test_expectation_without_any_date_is_not_evaluated(service):
    undated = _given_detection_expectation()
    dated = _given_detection_expectation(end_date_age=timedelta(minutes=7))
    _given_risk_index_holds(service, _expectation_own_event())

    results = _when_collector_runs(service, undated, dated)

    _then_verdict_is(results, undated, PENDING)
    _then_verdict_is(results, dated, DETECTED)
    assert service.client_api.fetch_with_retry.call_count == 1


def test_malformed_date_counts_as_no_date(service):
    expectation = _given_detection_expectation(
        raw_dates={SignatureTypes.SIG_TYPE_END_DATE: "not-a-date"}
    )
    _given_risk_index_holds(service, _other_expectations_events())

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, PENDING)


def test_end_date_with_timezone_offset_is_compared_in_utc(service):
    end_date = _iso(datetime.now(UTC) - timedelta(minutes=21), timedelta(hours=2))
    expectation = _given_detection_expectation(
        raw_dates={SignatureTypes.SIG_TYPE_END_DATE: end_date}
    )
    _given_risk_index_holds(service, _other_expectations_events())

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, NOT_DETECTED)


def test_splunk_es_failure_is_still_reported_at_once(service):
    expectation = _given_detection_expectation(end_date_age=timedelta(minutes=7))
    service.client_api.fetch_with_retry.side_effect = SplunkESAPIError("boom")

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, NOT_DETECTED)


def test_prevention_expectation_is_still_answered_at_once(service):
    expectation = _given_detection_expectation(
        end_date_age=timedelta(minutes=7), expectation_cls=PreventionExpectation
    )

    results = _when_collector_runs(service, expectation)

    _then_verdict_is(results, expectation, "Not Prevented")
