from typing import Optional

import requests
from src.models.alert import (
    GetIncidentExtraDataResponse,
    GetIncidentsResponse,
    Incident,
)
from src.models.authentication import Authentication


class PaloAltoCortexXDRClientAPI:
    def __init__(self, auth: Authentication, fqdn: str) -> None:
        self._auth = auth
        self.fqdn = fqdn

    def get_incident_ids(
        self,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
    ) -> list[int]:
        filters = []

        # if start_time is not None:
        #     filters.append(
        #         {"field": "creation_time", "operator": "gte", "value": start_time}
        #     )
        #
        # if end_time is not None:
        #     filters.append({"field": "creation_time", "operator": "lte", "value": end_time})

        request_data = {}
        if len(filters) > 0:
            request_data["filters"] = filters

        url = f"https://api-{self.fqdn}/public_api/v1/incidents/get_incidents"
        headers = self._auth.get_headers()

        response = requests.post(
            url, headers=headers, json={"request_data": request_data}
        )
        response.raise_for_status()
        response = GetIncidentsResponse.model_validate(response.json())
        return [incident.incident_id for incident in response.reply.incidents]

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
