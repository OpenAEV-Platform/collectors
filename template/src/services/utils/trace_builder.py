"""Trace building utilities for Template expectation processing."""

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..model_data import TemplateData

LOG_PREFIX = "[TemplateTraceBuilder]"


class TraceBuilder:
    """Utility class for building trace information."""

    @staticmethod
    def create_data_trace(
        data: "TemplateData",
    ) -> dict[str, Any]:
        """Create trace information for a data.

        Args:
            data: Template data object.

        Returns:
            Dictionary containing trace information with alert name, link, date,
            and additional metadata.

        """
        logger = logging.getLogger(__name__)

        alert_name = "Template Alert"
        alert_link = "http://foo.bar"

        trace_data = {
            "alert_name": alert_name,
            "alert_link": alert_link,
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "additional_data": {
                "data_key_value": data.key,
                "data_source": "template",
            },
        }

        logger.debug(f"{LOG_PREFIX} Created trace data: {trace_data}")
        return trace_data
