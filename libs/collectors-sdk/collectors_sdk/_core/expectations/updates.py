"""Expectation updates: the outcome payload sent to the platform."""

from typing import Any

__all__ = ["ExpectationUpdates"]


class ExpectationUpdates:
    """Implements ``ExpectationUpdatePort``."""

    def outcome(
        self,
        success: bool,
        sender_id: Any,
        metadata: Any,
        success_label: str,
        failure_label: str,
    ) -> dict[str, Any]:
        return {
            "collector_id": sender_id,
            "result": (success_label if success else failure_label),
            "is_success": success,
            "metadata": metadata,
        }
