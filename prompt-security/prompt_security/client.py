"""Prompt Security (SentinelOne) client.

Replays an AI red-team inject's attack content through the Prompt Security protect API
(`POST {base_url}/api/protect`) and reads the enforcement decision, validating whether Prompt
Security detects / blocks the attack.

Note: Prompt Security was acquired by SentinelOne (2025) and is being integrated into the
SentinelOne platform; the protect endpoint / auth header below reflect the Prompt Security API and
may need adjustment for a given tenant. Both the base URL and the auth header name are configurable.
"""

import requests


class Verdict:
    def __init__(self, flagged: bool, blocked: bool, detail: str = "", link: str = ""):
        self.flagged = flagged
        self.blocked = blocked
        self.detail = detail
        self.link = link


class PromptSecurityClient:
    def __init__(self, config: dict, logger=None):
        self.base_url = (config.get("ps_base_url") or "").rstrip("/")
        self.app_id = config.get("ps_app_id")
        self.auth_header = config.get("ps_auth_header") or "APP-ID"
        self.logger = logger
        self.session = requests.Session()

    def scan(self, prompt: str, system_prompt: str | None = None) -> Verdict:
        if not self.base_url:
            raise ValueError(
                "Prompt Security base_url is not configured; set collector.base_url "
                "(config.yml) or COLLECTOR_BASE_URL (Docker environment)."
            )
        if not self.app_id:
            raise ValueError(
                "Prompt Security app_id is not configured; set collector.app_id "
                "(config.yml) or COLLECTOR_APP_ID (Docker environment)."
            )
        headers = {"Content-Type": "application/json", self.auth_header: self.app_id}
        body = {"prompt": prompt}
        if system_prompt:
            body["system_prompt"] = system_prompt
        resp = self.session.post(
            f"{self.base_url}/api/protect", headers=headers, json=body, timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        result = data.get("result", data)
        action = str(result.get("action", "")).lower()
        violations = result.get("violations") or []
        flagged = bool(violations) or action in ("block", "modify", "log")
        blocked = action == "block"
        detail = ""
        if violations:
            first = violations[0]
            if isinstance(first, dict):
                detail = first.get("type") or first.get("name", "")
            else:
                detail = str(first)
        # Only label as a violation when something was actually flagged; a benign
        # response (action: allow, no violations) keeps a neutral empty detail so
        # expectation metadata and trace names are not misleading for "Not Detected".
        if flagged and not detail:
            detail = "Prompt Security violation"
        return Verdict(
            flagged=flagged,
            blocked=blocked,
            detail=detail,
        )
