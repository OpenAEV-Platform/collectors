"""Trace building utilities for HTTPLogwatcher expectation processing."""

import logging
from datetime import datetime, timezone
from typing import Any

from src.models.logline import LogLine

LOG_PREFIX = "[TraceBuilder]"


class TraceBuilder:
    """Utility class for building trace information."""

    @staticmethod
    def create_logline_trace(
        logline: LogLine,
    ) -> dict[str, Any]:
        """Create trace information for a logline.

        Args:
            logline: HTTPLogwatcher LogLine object.

        Returns:
            Dictionary containing trace information with name, date,
            and additional metadata.

        """
        logger = logging.getLogger(__name__)

        trace_data = {
            "alert_name": "HTTPLogwatcher LogLine",
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "additional_data": {
                "data_source": "http_logwatcher",
                "log_source": logline.source,
            },
        }

        logger.debug(f"{LOG_PREFIX} Created trace data: {trace_data}")
        return trace_data
