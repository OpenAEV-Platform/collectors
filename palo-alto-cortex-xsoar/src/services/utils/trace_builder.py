"""Trace building utilities for PaloAltoCortexXSOAR expectation processing."""

import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

from src.models.incident import Alert

LOG_PREFIX = "[TraceBuilder]"

_API_SOAR_PREFIX = "api-soar-"


def _build_web_base_url(api_url: str) -> str:
    """Convert an API URL to the corresponding web console base URL.

    Strips the ``api-soar-`` prefix from the hostname when present and
    ensures a proper ``https://`` URL is returned.

    Args:
        api_url: Full API URL (scheme guaranteed by HttpUrl validation).

    Example:
        https://api-soar-filigran.crtx.fa.paloaltonetworks.com
        → https://filigran.crtx.fa.paloaltonetworks.com
    """
    parsed = urlparse(api_url.strip().rstrip("/"))
    host = (parsed.hostname or "").removeprefix(_API_SOAR_PREFIX)

    return urlunparse(("https", host, "", "", "", ""))


class TraceBuilder:
    """Utility class for building trace information."""

    @staticmethod
    def create_alert_trace(
        alert: Alert,
        api_url: str,
    ) -> dict[str, Any]:
        """Create trace information for an alert.

        Args:
            alert: PaloAltoCortexXSOAR alert object.
            api_url: API URL for PaloAltoCortexXSOAR instance.

        Returns:
            Dictionary containing trace information with alert name, link, date,
            and additional metadata.

        """
        logger = logging.getLogger(__name__)
        alert_link = ""
        if api_url and alert.alert_id:
            try:
                web_base = _build_web_base_url(api_url)
                alert_link = f"{web_base}/issue-view/{alert.alert_id}"
                logger.debug(f"{LOG_PREFIX} Generated alert URL: {alert_link}")
            except Exception as e:
                logger.error(f"{LOG_PREFIX} Error generating URL: {e}")
                alert_link = ""
        else:
            logger.warning(
                f"{LOG_PREFIX} Cannot generate URL - api_url='{api_url}', alert_id='{alert.alert_id}'"
            )

        alert_name = f"PaloAltoCortexXSOAR Alert {alert.alert_id}"

        trace_data = {
            "alert_name": alert_name,
            "alert_link": alert_link,
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "additional_data": {
                "alert_id": alert.alert_id,
                "case_id": alert.case_id,
                "data_source": "palo_alto_cortex_xsoar",
            },
        }

        logger.debug(f"{LOG_PREFIX} Created trace data: {trace_data}")
        return trace_data
