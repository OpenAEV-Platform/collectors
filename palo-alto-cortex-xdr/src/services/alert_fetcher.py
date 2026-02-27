import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime

from requests.exceptions import (
    ConnectionError,
    RequestException,
    Timeout,
)
from src.models.alert import Alert
from src.services.client_api import PaloAltoCortexXDRClientAPI
from src.services.exception import (
    PaloAltoCortexXDRAPIError,
    PaloAltoCortexXDRNetworkError,
    PaloAltoCortexXDRValidationError,
)

LOG_PREFIX = "[AlertFetcher]"

PAGE_SIZE = 100

IMPLANT_PATTERN = re.compile(
    r"oaev-implant-[a-f0-9\-]+-agent-[a-f0-9\-]+", re.IGNORECASE
)


@dataclass
class FetchResult:
    alerts: list[Alert] = field(default_factory=list)
    process_names_by_alert_id: dict[int, list[str]] = field(default_factory=dict)


class AlertFetcher:
    """Fetcher for PaloAltoCortexXDR alert data using time-window based queries."""

    def __init__(self, client_api: PaloAltoCortexXDRClientAPI) -> None:
        if client_api is None:
            raise PaloAltoCortexXDRValidationError("client_api cannot be None")

        self.logger = logging.getLogger(__name__)
        self.client_api = client_api
        self.logger.debug(f"{LOG_PREFIX} Alert fetcher initialized")

    def fetch_alerts_for_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> FetchResult:
        """Fetch all alerts for a given time window.

        Returns:
            FetchResult with implant-bearing alerts and process names by alert_id.
        """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise PaloAltoCortexXDRValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise PaloAltoCortexXDRValidationError("start_time must be before end_time")

        try:
            start_ms = int(start_time.timestamp()) * 1000

            all_alerts = self._fetch_all_alerts(start_ms)

            if not all_alerts:
                self.logger.info(f"{LOG_PREFIX} No alerts found for time window")
                return FetchResult()

            # Split: alerts with implant in events (direct) vs without
            direct_alerts: list[Alert] = []
            needs_enrichment: list[Alert] = []
            process_names_by_alert_id: dict[int, list[str]] = {}

            for alert in all_alerts:
                implant_names = _extract_implant_names_from_events(alert)
                if implant_names:
                    direct_alerts.append(alert)
                    process_names_by_alert_id[alert.alert_id] = implant_names
                else:
                    needs_enrichment.append(alert)

            self.logger.info(
                f"{LOG_PREFIX} Found {len(all_alerts)} alerts: "
                f"{len(direct_alerts)} with direct implant, "
                f"{len(needs_enrichment)} need enrichment"
            )

            # Enrich alerts without direct implant via get_original_alerts
            enriched_alerts: list[Alert] = []
            if needs_enrichment:
                enriched_alerts, enriched_names = self._enrich_alerts(needs_enrichment)
                process_names_by_alert_id.update(enriched_names)

            all_implant_alerts = direct_alerts + enriched_alerts

            self.logger.info(
                f"{LOG_PREFIX} After enrichment: {len(all_implant_alerts)} total implant alerts "
                f"({len(direct_alerts)} direct + {len(enriched_alerts)} enriched)"
            )

            return FetchResult(
                alerts=all_implant_alerts,
                process_names_by_alert_id=process_names_by_alert_id,
            )

        except (ConnectionError, Timeout) as e:
            raise PaloAltoCortexXDRNetworkError(
                f"Network error fetching alerts for time window: {e}"
            ) from e
        except RequestException as e:
            raise PaloAltoCortexXDRAPIError(
                f"HTTP request failed fetching alerts for time window: {e}"
            ) from e
        except Exception as e:
            raise PaloAltoCortexXDRAPIError(
                f"Error fetching alerts for time window: {e}"
            ) from e

    def _fetch_all_alerts(self, creation_time_ms: int) -> list[Alert]:
        """Paginate through get_alerts to retrieve all alerts."""
        all_alerts: list[Alert] = []
        search_from = 0

        while True:
            response = self.client_api.get_alerts(
                creation_time=creation_time_ms,
                search_from=search_from,
                search_to=search_from + PAGE_SIZE,
            )

            alerts = response.reply.alerts
            all_alerts.extend(alerts)

            total = response.reply.total_count
            if total is None or len(all_alerts) >= total:
                break

            search_from += PAGE_SIZE

        return all_alerts

    def _enrich_alerts(
        self, alerts: list[Alert]
    ) -> tuple[list[Alert], dict[int, list[str]]]:
        """Enrich alerts without direct implant by calling get_original_alerts."""
        alert_ids = [str(a.alert_id) for a in alerts]
        alert_by_id = {a.alert_id: a for a in alerts}

        enriched_alerts: list[Alert] = []
        enriched_names: dict[int, list[str]] = {}

        try:
            original_alerts = self.client_api.get_original_alerts(alert_ids)
        except Exception as e:
            self.logger.warning(
                f"{LOG_PREFIX} Failed to get original alerts for enrichment: {e}"
            )
            return enriched_alerts, enriched_names

        for original in original_alerts:
            alert_id = original.get("internal_id")
            raw_json = original.get("original_alert_json", "")

            if not raw_json or alert_id is None:
                continue

            try:
                parsed = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
                implant_names = _extract_implant_names_from_original(parsed)

                if implant_names and alert_id in alert_by_id:
                    enriched_alerts.append(alert_by_id[alert_id])
                    enriched_names[alert_id] = implant_names
                    self.logger.debug(
                        f"{LOG_PREFIX} Enriched alert {alert_id} with implants: {implant_names}"
                    )
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.warning(
                    f"{LOG_PREFIX} Failed to parse original alert {alert_id}: {e}"
                )

        return enriched_alerts, enriched_names


def _extract_implant_names_from_events(alert: Alert) -> list[str]:
    """Extract oaev-implant filenames from alert events."""
    names = []
    for name in alert.get_process_image_names():
        if "oaev-implant-" in name.lower():
            names.append(name)
    return names


def _extract_implant_names_from_original(parsed: dict) -> list[str]:
    """Extract oaev-implant filenames from original alert messageData.processes."""
    implant_names: set[str] = set()

    processes = parsed.get("messageData", {}).get("processes", [])
    for proc in processes:
        cmd = proc.get("commandLine", "")
        matches = IMPLANT_PATTERN.findall(cmd)
        implant_names.update(matches)

    internals = (
        parsed.get("messageData", {}).get("dynamicAnalysis", {}).get("internals", [])
    )
    for inter in internals:
        image_name = inter.get("attributes", {}).get("image_name", "") + inter.get(
            "attributes", {}
        ).get("command_line", "")
        matches = IMPLANT_PATTERN.findall(image_name)
        implant_names.update(matches)

    return list(implant_names)
