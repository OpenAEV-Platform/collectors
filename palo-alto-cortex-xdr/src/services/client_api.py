from typing import Any, Optional

import requests
from src.models.alert import (
    GetAlertsResponse,
    GetIncidentExtraDataResponse,
    Incident,
)
from src.models.authentication import Authentication


class PaloAltoCortexXDRClientAPI:
    def __init__(self, auth: Authentication, fqdn: str) -> None:
        self._auth = auth
        self.fqdn = fqdn

    def get_alerts(
        self,
        creation_time: Optional[int] = None,
        search_from: int = 0,
        search_to: int = 100,
    ) -> GetAlertsResponse:
        request_data: dict = {
            "search_from": search_from,
            "search_to": search_to,
        }

        filters = []
        if creation_time is not None:
            filters.append(
                {"field": "creation_time", "operator": "gte", "value": creation_time}
            )

        if filters:
            request_data["filters"] = filters

        url = f"https://api-{self.fqdn}/public_api/v1/alerts/get_alerts_multi_events"
        headers = self._auth.get_headers()

        response = requests.post(
            url, headers=headers, json={"request_data": request_data}
        )
        response.raise_for_status()
        return GetAlertsResponse.model_validate(response.json())

    def get_original_alerts(
        self,
        alert_ids: list[str],
    ) -> list[dict[str, Any]]:
        request_data = {"alert_id_list": alert_ids}

        url = f"https://api-{self.fqdn}/public_api/v1/alerts/get_original_alerts"
        headers = self._auth.get_headers()

        response = requests.post(
            url, headers=headers, json={"request_data": request_data}
        )
        response.raise_for_status()
        return response.json().get("reply", {}).get("alerts", [])

    def get_incident_extra_data(
        self,
        incident_id: int,
    ) -> Incident:
        request_data = {"incident_id": str(incident_id)}

        url = f"https://api-{self.fqdn}/public_api/v1/incidents/get_incident_extra_data"
        headers = self._auth.get_headers()

        response = requests.post(
            url, headers=headers, json={"request_data": request_data}
        )
        response.raise_for_status()
        response = GetIncidentExtraDataResponse.model_validate(response.json())
        return response.reply
