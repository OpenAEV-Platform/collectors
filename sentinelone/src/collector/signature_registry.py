"""Signature Registry for dynamic expectation handling."""

from enum import Enum
from typing import Any, Callable

from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from .models import ExpectationResult


class ExpectationHandlerType(Enum):
    """Types of expectation handlers."""

    DETECTION = "detection"
    PREVENTION = "prevention"


class SignatureRegistry:
    """Simple registry for managing signature subscriptions and expectation handlers.

    This registry allows components to dynamically register:
    - Which signature types they're interested in
    - How to handle different types of expectations

    Keeps it simple by using basic data structures and clear interfaces.
    """

    def __init__(self) -> None:
        """Initialize the registry.

        Creates empty data structures for managing signature subscriptions
        and expectation handlers.
        """
        self._subscribed_signatures: set[SignatureTypes] = set()
        self._handlers: dict[
            ExpectationHandlerType, Callable[[Any, Any], ExpectationResult]
        ] = {}
        self._handler_signatures: dict[ExpectationHandlerType, set[SignatureTypes]] = {}

    def subscribe_to_signatures(self, signature_types: list[SignatureTypes]) -> None:
        """Subscribe to specific signature types.

        Args:
            signature_types: List of signature types to subscribe to.

        """
        self._subscribed_signatures.update(signature_types)

    def register_handler(
        self,
        handler_type: ExpectationHandlerType,
        handler_func: Callable[[Any, Any], ExpectationResult],
        signature_types: list[SignatureTypes],
    ) -> None:
        """Register an expectation handler for specific signature types.

        Args:
            handler_type: Type of handler (detection/prevention).
            handler_func: Function to handle expectations.
            signature_types: Signature types this handler supports.

        """
        self._handlers[handler_type] = handler_func
        self._handler_signatures[handler_type] = set(signature_types)

        self.subscribe_to_signatures(signature_types)

    def get_subscribed_signatures(self) -> list[SignatureTypes]:
        """Get all subscribed signature types.

        Returns:
            List of subscribed signature types.

        """
        return list(self._subscribed_signatures)

    def has_handler_for_signatures(
        self,
        handler_type: ExpectationHandlerType,
        signature_types: list[SignatureTypes],
    ) -> bool:
        """Check if a handler supports the given signature types.

        Args:
            handler_type: Type of handler to check.
            signature_types: Signature types to check.

        Returns:
            True if handler supports any of the signature types.

        """
        if handler_type not in self._handler_signatures:
            return False

        handler_sigs = self._handler_signatures[handler_type]
        return any(sig in handler_sigs for sig in signature_types)

    def get_handler(
        self, handler_type: ExpectationHandlerType
    ) -> Callable[[Any, Any], ExpectationResult]:
        """Get handler function for the given type.

        Args:
            handler_type: Type of handler to retrieve.

        Returns:
            Handler function.

        Raises:
            KeyError: If no handler registered for the type.

        """
        if handler_type not in self._handlers:
            raise KeyError(f"No handler registered for type: {handler_type}")
        return self._handlers[handler_type]

    def is_signature_supported(self, signature_type: SignatureTypes) -> bool:
        """Check if a signature type is supported by any registered handler.

        Args:
            signature_type: Signature type to check.

        Returns:
            True if supported.

        """
        return signature_type in self._subscribed_signatures

    def get_handler_types(self) -> list[ExpectationHandlerType]:
        """Get all registered handler types.

        Returns:
            List of registered handler types.

        """
        return list(self._handlers.keys())

    def clear(self) -> None:
        """Clear all registrations.

        Removes all signature subscriptions and handler registrations.
        Useful for testing and cleanup scenarios.
        """
        self._subscribed_signatures.clear()
        self._handlers.clear()
        self._handler_signatures.clear()


_registry = SignatureRegistry()


def get_registry() -> SignatureRegistry:
    """Get the global signature registry instance.

    Returns:
        The global registry instance.

    """
    return _registry
