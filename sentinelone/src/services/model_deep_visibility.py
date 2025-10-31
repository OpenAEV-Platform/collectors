"""SentinelOne Deep Visibility Models.

This module provides Pydantic models for Deep Visibility operations.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, PrivateAttr


def utc_now_iso() -> str:
    """Get current UTC time in ISO format with Z suffix.

    Returns:
        Current UTC timestamp as ISO format string with Z suffix.

    """
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"


class SearchCriteria(BaseModel):
    """Search criteria for Deep Visibility queries."""

    parent_process_name: Optional[str] = Field(
        None, description="Parent process name to search for"
    )
    process_name: Optional[str] = Field(None, description="Process name to search for")
    start_date: Optional[str] = Field(
        None, description="Start date for the search in ISO format"
    )
    to_date: Optional[str] = Field(
        None, description="End date for the search in ISO format"
    )

    def model_post_init(self, __context: Any) -> None:
        """Set default to_date if not provided.

        Args:
            __context: Pydantic model context (unused).

        """
        if self.to_date is None:
            self.to_date = utc_now_iso()


class DeepVisibilityEvent(BaseModel):
    """Deep Visibility event model."""

    src_proc_parent_name: Optional[str] = Field(
        None, description="Source process parent name"
    )
    src_proc_name: Optional[str] = Field(None, description="Source process name")
    tgt_file_sha1: Optional[str] = Field(None, description="Target file SHA1 hash")
    _raw: Optional[dict[str, Any]] = PrivateAttr(default=None)


class DeepVisibilityResponse(BaseModel):
    """Response from Deep Visibility API."""

    data: list[DeepVisibilityEvent] = Field(
        default_factory=list, description="List of Deep Visibility events"
    )

    @classmethod
    def from_raw_response(
        cls, response_data: dict[str, Any]
    ) -> "DeepVisibilityResponse":
        """Create from raw API response.

        Args:
            response_data: Raw response data from the Deep Visibility API.

        Returns:
            DeepVisibilityResponse instance with parsed events.

        """
        events = []
        raw_events = response_data.get("data", [])

        for raw_event in raw_events:
            event = DeepVisibilityEvent(
                src_proc_parent_name=raw_event.get("srcProcParentName"),
                src_proc_name=raw_event.get("srcProcName"),
                tgt_file_sha1=raw_event.get("tgtFileSha1"),
                _raw=raw_event,
            )
            events.append(event)

        return cls(data=events)
