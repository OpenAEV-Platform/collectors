from typing import Optional

import requests
from src.models.authentication import Authentication
from src.models.incident import XSOARSearchIncidentsResponse

REQUESTS_TIMEOUT_SECONDS = 60


class PaloAltoCortexXSOARClientAPI:
    def __init__(self, auth: Authentication, api_url: str) -> None:
        self._auth = auth
        self.api_url = api_url

    def _build_url(self, path: str) -> str:
        """Build a full URL from the configured api_url and a path."""
        return f"{self.api_url.rstrip('/')}{path}"

    def search_incidents(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        search_from: int = 0,
        search_to: int = 100,
    ) -> XSOARSearchIncidentsResponse:
        url = self._build_url("/xsoar/public/v1/incidents/search")
        headers = self._auth.get_headers()

        size = search_to - search_from
        page = search_from // size if size > 0 else 0

        body = {
            "filter": {
                "page": page,
                "size": size,
                "sort": [{"field": "created", "asc": True}],
            }
        }

        if from_date:
            body["filter"]["fromDate"] = from_date

        if to_date:
            body["filter"]["toDate"] = to_date

        response = requests.post(
            url, headers=headers, json=body, timeout=REQUESTS_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        return XSOARSearchIncidentsResponse.model_validate(response.json())
