"""HiddenLayer AI Runtime Security (AIDR) client.

Replays an AI red-team inject's attack content through the HiddenLayer Interactions endpoint
(`POST {base_url}/detection/v1/interactions`) and reads the detection verdict, validating whether
HiddenLayer AIDR detects / blocks the attack.

SaaS auth is OAuth2 client-credentials (client id/secret -> bearer via auth.hiddenlayer.ai). For a
self-hosted AIDR container, leave the client id/secret empty and point base_url at the container.

Docs: https://docs.hiddenlayer.ai / https://dev.hiddenlayer.ai
"""

import time

import requests


class Verdict:
    def __init__(self, flagged: bool, blocked: bool, detail: str = "", link: str = ""):
        self.flagged = flagged
        self.blocked = blocked
        self.detail = detail
        self.link = link


class HiddenLayerClient:
    def __init__(self, config: dict, logger=None):
        self.base_url = (
            config.get("hl_base_url") or "https://api.us.hiddenlayer.ai"
        ).rstrip("/")
        self.auth_url = (
            config.get("hl_auth_url") or "https://auth.hiddenlayer.ai/oauth2/token"
        )
        self.client_id = config.get("hl_client_id")
        self.client_secret = config.get("hl_client_secret")
        self.logger = logger
        self.session = requests.Session()
        self._token = None
        self._token_expiry = 0.0

    def _bearer(self):
        if not self.client_id or not self.client_secret:
            return None  # self-hosted, unauthenticated
        now = time.time()
        if self._token and now < self._token_expiry - 30:
            return self._token
        # RFC 6749 (4.4.2): client-credentials token parameters go in the
        # form-encoded request body (application/x-www-form-urlencoded), not the
        # query string. requests sets that Content-Type automatically for a dict
        # passed as ``data``. Client auth stays as HTTP Basic via ``auth`` (the
        # form HiddenLayer's token endpoint accepts).
        resp = self.session.post(
            self.auth_url,
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data.get("access_token")
        self._token_expiry = now + int(data.get("expires_in", 600))
        return self._token

    def scan(self, prompt: str, system_prompt: str | None = None) -> Verdict:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        headers = {"Content-Type": "application/json"}
        token = self._bearer()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = {
            "metadata": {"requester_id": "openaev-aev", "provider": "openaev"},
            "input": {"messages": messages},
        }
        resp = self.session.post(
            f"{self.base_url}/detection/v1/interactions",
            headers=headers,
            json=body,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        detections = data.get("detections") or data.get("results") or []
        action = str(data.get("action", "")).lower()
        blocked = action in ("block", "blocked") or bool(data.get("blocked"))
        # A block inherently means the attack was detected (prevention implies
        # detection), so a blocked verdict also counts as flagged.
        flagged = bool(detections) or bool(data.get("flagged")) or blocked
        detail = ""
        if isinstance(detections, list) and detections:
            first = detections[0]
            if isinstance(first, dict):
                detail = (
                    first.get("detection") or first.get("type") or first.get("name", "")
                )
            else:
                detail = str(first)
        # Only surface a detection detail when something was actually detected or
        # blocked; otherwise keep it neutral so a "Not Detected" verdict is not
        # labelled with a misleading detection string in the expectation metadata.
        if flagged:
            detail = detail or "HiddenLayer AIDR detection"
        else:
            detail = "No detection"
        return Verdict(
            flagged=flagged,
            blocked=blocked,
            detail=detail,
        )
