from http.cookiejar import DefaultCookiePolicy
from typing import Optional

from requests import Session
from requests.adapters import HTTPAdapter
from src.models.authentication import Authentication
from src.models.incident import XSOARSearchIncidentsResponse
from urllib3.util import Retry

REQUESTS_TIMEOUT_SECONDS = 60


class PaloAltoCortexXSOARClientAPI:
    def __init__(self, auth: Authentication, api_url: str) -> None:
        self._auth = auth
        self.api_url = api_url

        self.session = self._prepare_session()

    def _build_url(self, path: str) -> str:
        """Build a full URL from the configured api_url and a path."""
        return f"{self.api_url.rstrip('/')}{path}"

    def _prepare_session(self) -> Session:
        """Preparing a session with automatic retries (with increasing backoff) and no cookies"""
        retries = Retry(
            total=5,
            allowed_methods=["POST"],
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=0.5,
            backoff_jitter=0.2,
        )
        s = Session()
        s.mount("http://", HTTPAdapter(max_retries=retries))
        s.mount("https://", HTTPAdapter(max_retries=retries))
        s.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        return s

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

        response = self.session.post(
            url, headers=headers, json=body, timeout=REQUESTS_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        return XSOARSearchIncidentsResponse.model_validate(response.json())
