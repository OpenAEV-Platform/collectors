"""Tests for the SignatureRegistry."""

import pytest
from pyoaev.signatures.types import SignatureTypes
from src.collector.models import ExpectationResult
from src.collector.signature_registry import (
    ExpectationHandlerType,
    SignatureRegistry,
    get_registry,
)

SOURCE_IP = SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS
TARGET_IP = SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS


def _handler(expectation, helper) -> ExpectationResult:
    """Return a trivial valid result (test handler)."""
    return ExpectationResult(expectation_id="x", is_valid=True)


class TestSignatureRegistry:
    """Test cases for SignatureRegistry."""

    def test_subscribe_and_get_signatures(self):
        """Subscribed signatures are returned by the registry."""
        registry = SignatureRegistry()
        registry.subscribe_to_signatures([SOURCE_IP])
        assert SOURCE_IP in registry.get_subscribed_signatures()  # noqa: S101

    def test_register_handler(self):
        """Registering a handler records it and its signatures."""
        registry = SignatureRegistry()
        registry.register_handler(
            ExpectationHandlerType.DETECTION, _handler, [SOURCE_IP]
        )

        assert (  # noqa: S101
            registry.get_handler(ExpectationHandlerType.DETECTION) is _handler
        )
        assert registry.has_handler_for_signatures(  # noqa: S101
            ExpectationHandlerType.DETECTION, [SOURCE_IP]
        )
        assert registry.is_signature_supported(SOURCE_IP)  # noqa: S101
        assert (
            ExpectationHandlerType.DETECTION in registry.get_handler_types()
        )  # noqa: S101

    def test_has_handler_false_when_unregistered(self):
        """An unregistered handler type reports no support."""
        registry = SignatureRegistry()
        assert not registry.has_handler_for_signatures(  # noqa: S101
            ExpectationHandlerType.PREVENTION, [SOURCE_IP]
        )

    def test_has_handler_false_without_overlap(self):
        """A handler reports no support for unrelated signatures."""
        registry = SignatureRegistry()
        registry.register_handler(
            ExpectationHandlerType.DETECTION, _handler, [SOURCE_IP]
        )
        assert not registry.has_handler_for_signatures(  # noqa: S101
            ExpectationHandlerType.DETECTION, [TARGET_IP]
        )

    def test_get_handler_missing_raises(self):
        """Retrieving a missing handler raises KeyError."""
        registry = SignatureRegistry()
        with pytest.raises(KeyError):
            registry.get_handler(ExpectationHandlerType.DETECTION)

    def test_clear(self):
        """Clearing the registry removes all registrations."""
        registry = SignatureRegistry()
        registry.register_handler(
            ExpectationHandlerType.DETECTION, _handler, [SOURCE_IP]
        )
        registry.clear()
        assert registry.get_subscribed_signatures() == []  # noqa: S101
        assert registry.get_handler_types() == []  # noqa: S101

    def test_get_registry_is_singleton(self):
        """The module-level registry getter returns a singleton."""
        assert get_registry() is get_registry()  # noqa: S101
