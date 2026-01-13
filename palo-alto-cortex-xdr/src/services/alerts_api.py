from typing import Optional

import requests
from src.models.alerts import GetAlertsResponse
from src.models.authentication import Authentication


class AlertsAPI:
    def __init__(self, auth: Authentication, fqdn: str) -> None:
        self._auth = auth
        self._fqdn = fqdn

    def _get_url(self) -> str:
        return f"https://api-{self._fqdn}/public_api/v1/alerts/get_alerts"

    def get_alerts(
        self,
        start_time: int = None,
        end_time: int = None,
        search_from: int = None,
        search_to: int = None,
    ) -> Optional[GetAlertsResponse]:
        """
        Get a list of alerts with multiple events.

        :param start_time: Timestamp of the Creation time. Also known as detection_timestamp.
        :param end_time: Timestamp of the Creation time. Also known as detection_timestamp.
        :param search_to: Integer representing the end offset within the result set after which you do not want incidents returned.
        :param search_from: Integer representing the starting offset within the query result set from which you want incidents returned.
        :return: Returns a GetAlertsResponse object if successful.
        """
        filters = []

        if start_time is not None:
            filters.append(
                {"field": "creation_time", "operator": "gte", "value": start_time}
            )

        if end_time is not None:
            filters.append(
                {"field": "creation_time", "operator": "lte", "value": end_time}
            )

        request_data = {}
        if len(filters) > 0:
            request_data["filters"] = filters
        if search_from is not None:
            request_data["search_from"] = search_from
        if search_to is not None:
            request_data["search_to"] = search_to

        url = self._get_url()
        headers = self._auth.get_headers()

        response = requests.post(
            url, headers=headers, json={"request_data": request_data}
        )
        response.raise_for_status()
        return GetAlertsResponse.model_validate(response.json())
