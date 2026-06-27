"""Cisco AI Defense (Robust Intelligence) client.

Replays an AI red-team inject's attack content through the Cisco AI Defense inspection API
(`POST {base_url}/api/v1/inspect/prompt`) and reads the safety verdict, validating whether Cisco AI
Defense detects / blocks the attack.

Note: Cisco AI Defense (built on the acquired Robust Intelligence engine) exposes its inspection API
to tenants; the endpoint path and auth header below reflect the documented shape and are
configurable, since the public API surface is still consolidating.
"""

from urllib.parse import urlparse

import requests


class Verdict:
    def __init__(self, flagged: bool, blocked: bool, detail: str = "", link: str = ""):
        self.flagged = flagged
        self.blocked = blocked
        self.detail = detail
        self.link = link


class CiscoAiDefenseClient:
    def __init__(self, config: dict, logger=None):
        self.base_url = (config.get("cisco_base_url") or "").rstrip("/")
        self.api_key = config.get("cisco_api_key")
        self.auth_header = (
            config.get("cisco_auth_header") or "X-Cisco-AI-Defense-Api-Key"
        )
        self.logger = logger
        self.session = requests.Session()

    def scan(self, prompt: str, system_prompt: str | None = None) -> Verdict:
        if not self.base_url:
            raise ValueError(
                "Cisco AI Defense base_url is not configured; set collector.base_url "
                "(COLLECTOR_BASE_URL) to the inspection API base URL."
            )
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "Cisco AI Defense base_url must be a valid http(s) URL including a host, "
                "e.g. https://<region>.api.inspect.aidefense.security.cisco.com; "
                f"got {self.base_url!r}. Set collector.base_url (COLLECTOR_BASE_URL) accordingly."
            )
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers[self.auth_header] = self.api_key
        body = {"messages": messages}
        resp = self.session.post(
            f"{self.base_url}/api/v1/inspect/prompt",
            headers=headers,
            json=body,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        is_safe = data.get("is_safe")
        classifications = data.get("classifications") or data.get("rules") or []
        action = str(data.get("action", "")).lower()
        # PREVENTION is only satisfied by an explicit block action; an unsafe verdict or a
        # classification without a block maps to DETECTION only.
        blocked = action in ("block", "blocked")
        flagged = (is_safe is False) or bool(classifications) or blocked
        detail = ""
        if isinstance(classifications, list) and classifications:
            first = classifications[0]
            if isinstance(first, dict):
                detail = (
                    first.get("classification")
                    or first.get("name")
                    or first.get("rule_name", "")
                )
            else:
                detail = str(first)
        return Verdict(
            flagged=flagged,
            blocked=blocked,
            detail=detail or "Cisco AI Defense classification",
        )
