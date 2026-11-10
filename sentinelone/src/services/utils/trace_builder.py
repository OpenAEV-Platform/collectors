"""Trace building utilities for SentinelOne expectation processing."""

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from ..model_threat import UNIFIED_ALERT_SOURCE

if TYPE_CHECKING:
    from ..model_threat import SentinelOneThreat

LOG_PREFIX = "[SentinelOneTraceBuilder]"

# Console path of one Unified Alert, formatted with ``alert_id``. SentinelOne
# does not document it, so it is left empty until confirmed from the console;
# while empty, Unified Alert traces link to the console root instead of a
# broken Threat overview URL.
UNIFIED_ALERT_LINK_PATH = ""


class TraceBuilder:
    """Utility class for building trace information."""

    @staticmethod
    def create_threat_trace(
        threat: "SentinelOneThreat",
        base_url: str,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Create trace information for a threat.

        Args:
            threat: SentinelOne threat object.
            base_url: Base URL for SentinelOne web interface.
            events: List of events associated with the threat.

        Returns:
            Dictionary containing trace information with alert name, link, date,
            and additional metadata.

        """
        logger = logging.getLogger(__name__)
        is_unified_alert = threat.source == UNIFIED_ALERT_SOURCE
        alert_link = ""
        if base_url and threat.threat_id:
            try:
                web_base = base_url.rstrip("/")
                encoded_threat_id = quote(threat.threat_id)
                if not is_unified_alert:
                    alert_link = (
                        f"{web_base}/incidents/threats/{encoded_threat_id}/overview"
                    )
                elif UNIFIED_ALERT_LINK_PATH:
                    alert_link = f"{web_base}{UNIFIED_ALERT_LINK_PATH.format(alert_id=encoded_threat_id)}"
                else:
                    # A Unified Alert is not a Threat: the threat overview URL
                    # would be broken. No documented deep link exists for an
                    # alert, so point to the console and carry the alert id in
                    # the trace name instead.
                    alert_link = web_base
                logger.debug(f"{LOG_PREFIX} Generated trace URL: {alert_link}")
            except Exception as e:
                logger.error(f"{LOG_PREFIX} Error generating URL: {e}")
                alert_link = ""
        else:
            logger.warning(
                f"{LOG_PREFIX} Cannot generate URL - base_url='{base_url}', threat_id='{threat.threat_id}'"
            )

        if is_unified_alert:
            alert_name = "SentinelOne Unified Alert"
            if threat.name:
                alert_name = f"{alert_name} - {threat.name}"
            if threat.hostname:
                alert_name = f"{alert_name} - {threat.hostname}"
            alert_name = f"{alert_name} (alert id {threat.threat_id})"
        else:
            alert_name = "SentinelOne Alert"
            if threat.hostname:
                alert_name = f"{alert_name} - {threat.hostname}"
            elif threat.threat_id:
                alert_name = f"{alert_name} {threat.threat_id}"

        trace_data = {
            "alert_name": alert_name,
            "alert_link": alert_link,
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "additional_data": {
                "threat_id": threat.threat_id,
                "hostname": threat.hostname,
                "is_mitigated": threat.is_mitigated,
                "is_static": threat.is_static,
                "events_count": len(events),
                "source": threat.source,
                "data_source": "sentinelone",
            },
        }

        logger.debug(f"{LOG_PREFIX} Created trace data: {trace_data}")
        return trace_data
