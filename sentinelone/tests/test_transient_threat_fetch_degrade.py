"""BDD: transient SentinelOne threat-fetch failures degrade after the retry window.

The retry rule is time-based, not count-based: the first failed attempt opens
a 10-minute retry window anchored at that moment; every collector cycle whose
elapsed time since the first attempt is within the window holds the
expectation pending (no verdict, re-fetched next cycle); the first cycle
after the window is the final attempt, which degrades to a negative verdict
("Not Detected" / "Not Prevented", is_success=False) instead of hanging
forever.

The cycle cadence is the collector's period; the rule only depends on
elapsed time:

    P1M: 1 opening + 10 in-window (t=1..10) + 1 final (t=11) = 12 attempts
    P2M: 1 opening + 5 in-window (t=2..10) + 1 final (t=12) = 7 attempts
    P1H: 1 opening + 0 in-window + 1 final (t=60) = 2 attempts

The pending results are is_valid=False/is_pending=True and pass through the
retry-window loop (_update_failures): in-window results are removed (no
verdict, re-fetched next cycle); once the window has elapsed the result
survives on the final attempt and degrades.
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest import mock

import requests
from pyoaev.apis.inject_expectation.model import DetectionExpectation
from pyoaev.apis.inject_expectation.model.expectation import ExpectationSignature
from pyoaev.signatures.types import SignatureTypes
from src.collector.expectation_handler import GenericExpectationHandler
from src.collector.expectation_manager import GenericExpectationManager
from src.services.expectation_service import SentinelOneExpectationService
from tests.services.fixtures.factories import create_test_config

T0 = datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)


class _FakeClock:
    """A wall clock that only moves when the test advances it."""

    def __init__(self, start: datetime = T0):
        self.now = start

    def advance(self, amount: timedelta) -> None:
        self.now = self.now + amount


def _build_expectation(end_value: str = "2024-01-15T00:00:00Z"):
    """Build a real Detection expectation that survives batch creation.

    Needs a valid UUID id and an end_date signature (strict end_date is on).
    """
    end_sig = ExpectationSignature(
        type=SignatureTypes.SIG_TYPE_END_DATE, value=end_value
    )
    return DetectionExpectation(
        inject_expectation_id=uuid.uuid4(),
        inject_expectation_signatures=[end_sig],
        api_client=mock.MagicMock(),
    )


def _transient_network_error(service):
    """Simulate a transient transport failure at the network boundary."""
    return mock.patch.object(
        service.client_api.session,
        "get",
        side_effect=requests.exceptions.ConnectionError(
            "simulated transient network failure"
        ),
    )


def _patched_clock(clock: _FakeClock):
    """Pin the service's retry-window clock to the fake clock."""
    return mock.patch.object(
        SentinelOneExpectationService, "_now", side_effect=lambda: clock.now
    )


def _negative_verdict_emitted(mock_oaev, expectation_id: str) -> bool:
    """True if the manager emitted a negative verdict for the expectation id."""
    if not mock_oaev.inject_expectation.bulk_update.called:
        return False
    bulk = mock_oaev.inject_expectation.bulk_update.call_args.kwargs.get(
        "inject_expectation_input_by_id"
    )
    entry = (bulk or {}).get(expectation_id)
    return bool(entry) and (
        entry.get("is_success") is False
        or entry.get("result") in ("Not Detected", "Not Prevented")
    )


def test_transient_failures_degrade_after_retry_window_one_minute_cadence():
    """P1M: 1 opening attempt + 10 in-window + 1 final = 12 attempts."""
    expectation = _build_expectation()
    service = SentinelOneExpectationService(config=create_test_config())
    detection_helper = mock.MagicMock()
    expectation_id = str(expectation.inject_expectation_id)

    assert service.retry_window == timedelta(
        minutes=10
    ), "Default retry window must be 10 minutes."

    clock = _FakeClock()
    attempts = 0
    with _patched_clock(clock), _transient_network_error(service):
        # Attempt 1 (t=0): opens the retry window, no verdict.
        results, _ = service.handle_batch_expectations([expectation], detection_helper)
        attempts += 1
        assert not results, "Opening attempt must hold pending, emit no verdict."

        # t=1..10: elapsed <= 10 min -> in window, still no verdict.
        for _ in range(10):
            clock.advance(timedelta(minutes=1))
            results, _ = service.handle_batch_expectations(
                [expectation], detection_helper
            )
            attempts += 1
            assert not results, (
                f"In-window transient failure (attempt {attempts}) must hold "
                "pending, emit no verdict."
            )

        # t=11: window elapsed -> final attempt degrades to a verdict.
        clock.advance(timedelta(minutes=1))
        results, _ = service.handle_batch_expectations([expectation], detection_helper)
        attempts += 1

    assert attempts == 12, f"P1M cadence must make 12 attempts, got {attempts}"
    assert len(results) == 1, (
        "The final attempt must emit exactly one verdict, " f"got {len(results)}"
    )
    assert results[0].expectation_id == expectation_id
    assert results[0].is_valid is False, (
        "After the retry window the expectation must degrade to a "
        "negative verdict (is_valid=False)."
    )
    assert results[0].is_pending is True


def test_transient_failures_degrade_after_retry_window_two_minute_cadence():
    """P2M: 1 opening attempt + 5 in-window (t=2..10) + 1 final (t=12) = 7."""
    expectation = _build_expectation()
    service = SentinelOneExpectationService(config=create_test_config())
    detection_helper = mock.MagicMock()
    expectation_id = str(expectation.inject_expectation_id)

    clock = _FakeClock()
    attempts = 0
    with _patched_clock(clock), _transient_network_error(service):
        # Attempt 1 (t=0): opens the retry window, no verdict.
        results, _ = service.handle_batch_expectations([expectation], detection_helper)
        attempts += 1
        assert not results, "Opening attempt must hold pending, emit no verdict."

        # t=2..10: elapsed <= 10 min -> in window, still no verdict.
        for _ in range(5):
            clock.advance(timedelta(minutes=2))
            results, _ = service.handle_batch_expectations(
                [expectation], detection_helper
            )
            attempts += 1
            assert not results, (
                f"In-window transient failure (attempt {attempts}) must hold "
                "pending, emit no verdict."
            )

        # t=12: window elapsed -> final attempt degrades to a verdict.
        clock.advance(timedelta(minutes=2))
        results, _ = service.handle_batch_expectations([expectation], detection_helper)
        attempts += 1

    assert attempts == 7, f"P2M cadence must make 7 attempts, got {attempts}"
    assert len(results) == 1
    assert results[0].expectation_id == expectation_id
    assert results[0].is_valid is False
    assert results[0].is_pending is True


def test_transient_failures_degrade_after_retry_window_one_hour_cadence():
    """P1H: 1 opening attempt + 0 in-window + 1 final (next run at t=60)
    = 2 attempts."""
    expectation = _build_expectation()
    service = SentinelOneExpectationService(config=create_test_config())
    detection_helper = mock.MagicMock()
    expectation_id = str(expectation.inject_expectation_id)

    clock = _FakeClock()
    attempts = 0
    with _patched_clock(clock), _transient_network_error(service):
        # Attempt 1 (t=0): opens the retry window, no verdict.
        results, _ = service.handle_batch_expectations([expectation], detection_helper)
        attempts += 1
        assert not results, "Opening attempt must hold pending, emit no verdict."

        # t=60: next collector run, far past the window -> final attempt.
        clock.advance(timedelta(hours=1))
        results, _ = service.handle_batch_expectations([expectation], detection_helper)
        attempts += 1

    assert attempts == 2, f"P1H cadence must make 2 attempts, got {attempts}"
    assert len(results) == 1
    assert results[0].expectation_id == expectation_id
    assert results[0].is_valid is False
    assert results[0].is_pending is True


def test_transient_failures_degrade_emits_negative_verdict_through_manager():
    """11 in-window service-level attempts emit no verdict; the first
    manager cycle after the window emits the negative verdict."""
    expectation = _build_expectation()
    service = SentinelOneExpectationService(config=create_test_config())
    handler = GenericExpectationHandler(service_provider=service)
    mock_oaev = mock.MagicMock()
    mock_oaev.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]
    manager = GenericExpectationManager(
        oaev_api=mock_oaev,
        collector_id="test-collector",
        expectation_handler=handler,
    )
    expectation_id = str(expectation.inject_expectation_id)
    detection_helper = mock.MagicMock()

    clock = _FakeClock()
    with _patched_clock(clock), _transient_network_error(service):
        # t=0..10: 11 attempts, all within the window -> no verdict.
        for _ in range(11):
            results, _ = service.handle_batch_expectations(
                [expectation], detection_helper
            )
            assert not results, "In-window transient failures must emit no verdict."
            clock.advance(timedelta(minutes=1))

        # t=11: driven through the full manager path -> final attempt.
        manager.process_expectations(detection_helper)

    assert _negative_verdict_emitted(mock_oaev, expectation_id), (
        "After the retry window the manager must emit a negative verdict "
        "(Not Detected / is_success=False), not hang the expectation forever."
    )
