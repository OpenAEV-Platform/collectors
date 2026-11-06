"""BDD: transient SentinelOne threat-fetch failure must not emit a negative verdict.

A transient transport failure (network drop / 5xx / 429) must leave the
expectation unresolved (pending) for the retry-window rule, rather than
emitting a "Not Detected" / "Not Prevented" update.

RED: this fails against the current implementation, which collapses every
fetch failure into a negative verdict and thereby resolves the expectation.
"""

import uuid
from unittest import mock

import requests
from pyoaev.apis.inject_expectation.model import DetectionExpectation
from pyoaev.apis.inject_expectation.model.expectation import ExpectationSignature
from pyoaev.signatures.types import SignatureTypes
from src.collector.expectation_handler import GenericExpectationHandler
from src.collector.expectation_manager import GenericExpectationManager
from src.services.expectation_service import SentinelOneExpectationService
from tests.services.fixtures.factories import create_test_config


def _build_expectation(cls, end_value: str = "2024-01-15T00:00:00Z"):
    """Build a real expectation (survives the manager's isinstance filter).

    The manager only processes real Detection/Prevention expectation models, so a
    plain Mock would be silently filtered out. A valid UUID id and an end_date
    signature are required to survive batch creation (strict end_date is on).
    """
    end_sig = ExpectationSignature(
        type=SignatureTypes.SIG_TYPE_END_DATE, value=end_value
    )
    return cls(
        inject_expectation_id=uuid.uuid4(),
        inject_expectation_signatures=[end_sig],
        api_client=mock.MagicMock(),
    )


def _build_manager(expectation):
    """Wire the real service -> handler -> manager over a mocked OpenAEV client."""
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
    return service, manager, mock_oaev


def _transient_network_error(service):
    """Simulate a transient transport failure at the network boundary."""
    return mock.patch.object(
        service.client_api.session,
        "get",
        side_effect=requests.exceptions.ConnectionError(
            "simulated transient network failure"
        ),
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


def test_transient_network_error_does_not_emit_negative_verdict():
    expectation = _build_expectation(DetectionExpectation)
    service, manager, mock_oaev = _build_manager(expectation)

    with _transient_network_error(service):
        manager.process_expectations(mock.MagicMock())

    assert not _negative_verdict_emitted(
        mock_oaev, str(expectation.inject_expectation_id)
    ), (
        "Transient network failure must leave the expectation pending, "
        "not emit a negative verdict."
    )  # noqa: S101
