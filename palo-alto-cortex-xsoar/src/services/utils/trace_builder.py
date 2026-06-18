"""Trace building utilities for PaloAltoCortexXSOAR expectation processing."""

import logging
from datetime import datetime, timezone
from typing import Any

from src.services.ioc_extractor import IncidentResult

LOG_PREFIX = "[TraceBuilder]"

_PALO_ALTO_DOMAIN = "fa.paloaltonetworks.com"


def _extract_incident_url(incident: IncidentResult) -> str:
    """Extract the PaloAlto console URL from incident indicators.

    Searches ``incident.indicators.url`` for the entry containing
    ``fa.paloaltonetworks.com``.

    Returns:
        The matching URL string, or empty string if not found.
    """
    for url in incident.indicators.url:
        if _PALO_ALTO_DOMAIN in url:
            return url
    return ""


class TraceBuilder:
    """Utility class for building trace information."""

    @staticmethod
    def create_incident_trace(
        incident: IncidentResult,
        api_url: str,
    ) -> dict[str, Any]:
        """Create trace information for an incident.

        Args:
            incident: IncidentResult object.
            api_url: API URL for PaloAltoCortexXSOAR instance (unused, kept for compatibility).

        Returns:
            Dictionary containing trace information with incident name, link, date,
            and additional metadata.

        """
        logger = logging.getLogger(__name__)
        incident_link = ""

        try:
            incident_link = _extract_incident_url(incident)
            if incident_link:
                logger.debug(f"{LOG_PREFIX} Found incident URL: {incident_link}")
            else:
                logger.warning(
                    f"{LOG_PREFIX} No PaloAlto URL found in incident {incident.id} indicators"
                )
        except Exception as e:
            logger.error(f"{LOG_PREFIX} Error extracting URL: {e}")
            incident_link = ""

        incident_name = f"PaloAltoCortexXSOAR Incident {incident.id}"

        trace_data = {
            "alert_name": incident_name,
            "alert_link": incident_link,
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "additional_data": {
                "incident_id": incident.id,
                "data_source": "palo_alto_cortex_xsoar",
            },
        }

        logger.debug(f"{LOG_PREFIX} Created trace data: {trace_data}")
        return trace_data
