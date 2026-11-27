"""Minimal read-only client for the OVHcloud API (v1).

Two authentication modes are supported:

- application key + application secret + consumer key: every request is signed with
  ``X-Ovh-Signature`` and timestamped with the server clock (``GET /auth/time``), as the
  official ``python-ovh`` library does;
- OAuth2 service account (client credentials): a bearer token is fetched from the OVHcloud
  authorization server of the selected endpoint and refreshed when it expires.

Only ``GET`` requests are issued: the collector never changes anything on the account.
"""

import hashlib
import json
import logging
import time
from typing import Any
from urllib.parse import urlencode

import requests

ENDPOINTS: dict[str, str] = {
    "ovh-eu": "https://eu.api.ovh.com/1.0",
    "ovh-ca": "https://ca.api.ovh.com/1.0",
    "ovh-us": "https://api.us.ovhcloud.com/1.0",
}

OAUTH2_TOKEN_URLS: dict[str, str] = {
    "ovh-eu": "https://www.ovh.com/auth/oauth2/token",
    "ovh-ca": "https://ca.ovh.com/auth/oauth2/token",
    "ovh-us": "https://us.ovhcloud.com/auth/oauth2/token",
}

RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
DEFAULT_TIMEOUT_SECONDS = 30
TOKEN_EXPIRY_MARGIN_SECONDS = 60


class OvhApiError(Exception):
    """An OVHcloud API call failed (after retries, or with a non retryable status)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def compute_signature(
    application_secret: str,
    consumer_key: str,
    method: str,
    url: str,
    body: str,
    timestamp: int,
) -> str:
    """Compute the ``X-Ovh-Signature`` header of a request.

    The signature is ``$1$`` followed by the SHA-1 hex digest of the application secret,
    the consumer key, the HTTP method, the full URL (query string included), the body and
    the timestamp, joined with ``+``.

    Args:
        application_secret: The application secret.
        consumer_key: The consumer key.
        method: The HTTP method, upper case.
        url: The full request URL, query string included.
        body: The request body ("" for a GET).
        timestamp: The request timestamp, in server time.

    Returns:
        The signature header value.

    """
    payload = "+".join(
        [application_secret, consumer_key, method.upper(), url, body, str(timestamp)]
    )
    # SHA-1 is imposed by the OVHcloud API signature scheme, not a choice of ours.
    digest = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"$1${digest}"


class OvhClient:
    """Read-only OVHcloud API client with retries on throttling and server errors."""

    def __init__(
        self,
        endpoint: str = "ovh-eu",
        application_key: str | None = None,
        application_secret: str | None = None,
        consumer_key: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if endpoint not in ENDPOINTS:
            raise ValueError(
                f"Unknown OVHcloud endpoint '{endpoint}', expected one of {sorted(ENDPOINTS)}"
            )
        self.endpoint = endpoint
        self.base_url = ENDPOINTS[endpoint]
        self.application_key = application_key
        self.application_secret = application_secret
        self.consumer_key = consumer_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.timeout_seconds = timeout_seconds
        self.session = session or requests.Session()
        self.logger = logger or logging.getLogger(__name__)

        self.use_oauth2 = bool(client_id and client_secret)
        if not self.use_oauth2 and not (
            application_key and application_secret and consumer_key
        ):
            raise ValueError(
                "OVHcloud credentials are incomplete: provide either an application key, "
                "an application secret and a consumer key, or an OAuth2 client id and "
                "client secret"
            )

        self._time_delta: int | None = None
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0

    # -- authentication ----------------------------------------------------------------

    def _server_time_delta(self) -> int:
        """Difference between the OVHcloud server clock and the local clock, cached."""
        if self._time_delta is None:
            response = self._send("GET", f"{self.base_url}/auth/time", {})
            server_time = int(response.json())
            self._time_delta = server_time - int(time.time())
        return self._time_delta

    def _oauth2_token(self) -> str:
        """Return a valid OAuth2 bearer token, fetching a new one when needed."""
        if self._access_token and time.time() < self._token_expires_at:
            return self._access_token
        response = self.session.post(
            OAUTH2_TOKEN_URLS[self.endpoint],
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "all",
            },
            timeout=self.timeout_seconds,
        )
        if response.status_code != 200:
            raise OvhApiError(
                f"OVHcloud OAuth2 token request failed: HTTP {response.status_code}",
                response.status_code,
            )
        payload = response.json()
        self._access_token = str(payload["access_token"])
        expires_in = int(payload.get("expires_in", 3600))
        self._token_expires_at = time.time() + max(
            expires_in - TOKEN_EXPIRY_MARGIN_SECONDS, 0
        )
        return self._access_token

    def _auth_headers(self, url: str) -> dict[str, str]:
        if self.use_oauth2:
            return {"Authorization": f"Bearer {self._oauth2_token()}"}
        timestamp = int(time.time()) + self._server_time_delta()
        return {
            "X-Ovh-Application": str(self.application_key),
            "X-Ovh-Consumer": str(self.consumer_key),
            "X-Ovh-Timestamp": str(timestamp),
            "X-Ovh-Signature": compute_signature(
                str(self.application_secret),
                str(self.consumer_key),
                "GET",
                url,
                "",
                timestamp,
            ),
        }

    # -- transport -----------------------------------------------------------------------

    def _send(
        self, method: str, url: str, headers: dict[str, str]
    ) -> requests.Response:
        """Send a request, retrying on 429 / 5xx and connection errors with backoff."""
        attempt = 0
        while True:
            try:
                response = self.session.request(
                    method, url, headers=headers, timeout=self.timeout_seconds
                )
            except requests.RequestException as err:
                if attempt >= self.max_retries:
                    raise OvhApiError(f"GET {url} failed: {err}") from err
                self._sleep(attempt, None)
                attempt += 1
                continue
            if (
                response.status_code in RETRYABLE_STATUSES
                and attempt < self.max_retries
            ):
                self.logger.debug(
                    f"OVHcloud API answered {response.status_code} on {url}, retrying"
                )
                self._sleep(attempt, response.headers.get("Retry-After"))
                attempt += 1
                continue
            if response.status_code != 200:
                raise OvhApiError(
                    f"GET {url} failed: HTTP {response.status_code} {response.text[:200]}",
                    response.status_code,
                )
            return response

    def _sleep(self, attempt: int, retry_after: str | None) -> None:
        delay = self.backoff_seconds * (2**attempt)
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except ValueError:
                pass
        time.sleep(delay)

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Issue an authenticated GET on an API path and return the decoded JSON.

        Args:
            path: The API path, starting with ``/`` (e.g. ``/dedicated/server``).
            params: Optional query parameters.

        Returns:
            The decoded JSON body.

        Raises:
            OvhApiError: When the call fails after the retries.

        """
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        response = self._send("GET", url, self._auth_headers(url))
        if not response.content:
            return None
        try:
            return response.json()
        except json.JSONDecodeError as err:
            raise OvhApiError(f"GET {url} returned a non JSON body") from err
