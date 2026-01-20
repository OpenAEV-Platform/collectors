"""Trace building utilities for PaloAltoCortexXDR expectation processing."""

import logging
from datetime import datetime, timezone
from typing import Any

from src.models.alert import Alert

LOG_PREFIX = "[TraceBuilder]"


class TraceBuilder:
    """Utility class for building trace information."""

    @staticmethod
    def create_alert_trace(
        alert: Alert,
        fqdn: str,
    ) -> dict[str, Any]:
        """Create trace information for an alert.

        Args:
            alert: PaloAltoCortexXDR alert object.
            fqdn: Base URL for PaloAltoCortexXDR web interface.

        Returns:
            Dictionary containing trace information with alert name, link, date,
            and additional metadata.

        """
        logger = logging.getLogger(__name__)
        alert_link = ""
        if fqdn and alert.alert_id:
            try:
                web_base = "https://" + fqdn.rstrip("/")
                alert_link = f"{web_base}/alerts/{alert.alert_id}/{alert.case_id}"
                logger.debug(f"{LOG_PREFIX} Generated alert URL: {alert_link}")
            except Exception as e:
                logger.error(f"{LOG_PREFIX} Error generating URL: {e}")
                alert_link = ""
        else:
            logger.warning(
                f"{LOG_PREFIX} Cannot generate URL - fqdn='{fqdn}', alert_id='{alert.alert_id}'"
            )

        alert_name = f"PaloAltoCortexXDR Alert {alert.alert_id}"

        trace_data = {
            "alert_name": alert_name,
            "alert_link": alert_link,
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "additional_data": {
                "alert_id": alert.alert_id,
                "case_id": alert.case_id,
                "data_source": "palo_alto_cortex_xdr",
            },
        }

        logger.debug(f"{LOG_PREFIX} Created trace data: {trace_data}")
        return trace_data
