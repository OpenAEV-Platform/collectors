"""Lakera Guard (Check Point AI Security) client.

Replays an AI red-team inject's attack content through the Lakera Guard screening API
(`POST https://api.lakera.ai/v2/guard`) and reads the flagging decision, validating whether the
configured Lakera policy detects / would block the attack.

Docs: https://docs.lakera.ai/docs/api/guard
"""

import requests


class Verdict:
    def __init__(self, flagged: bool, blocked: bool, detail: str = "", link: str = ""):
        self.flagged = flagged
        self.blocked = blocked
        self.detail = detail
        self.link = link


class LakeraClient:
    def __init__(self, config: dict, logger=None):
        self.base_url = (
            config.get("lakera_base_url") or "https://api.lakera.ai/v2"
        ).rstrip("/")
        self.api_key = config.get("lakera_api_key")
        self.project_id = config.get("lakera_project_id")
        blocking_policy = config.get("lakera_blocking_policy")
        self.blocking_policy = (
            True if blocking_policy is None else bool(blocking_policy)
        )
        self.logger = logger
        self.session = requests.Session()

    def scan(self, prompt: str, system_prompt: str | None = None) -> Verdict:
        if not self.api_key:
            raise ValueError(
                "Lakera Guard is not configured: api_key is required (set COLLECTOR_API_KEY)."
            )
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        body = {"messages": messages, "breakdown": True}
        if self.project_id:
            body["project_id"] = self.project_id
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        resp = self.session.post(
            f"{self.base_url}/guard", headers=headers, json=body, timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        flagged = bool(data.get("flagged"))
        detail = ""
        for item in data.get("breakdown", []) or []:
            if item.get("detected"):
                detail = item.get("detector_type") or item.get("detector_id") or ""
                break
        # Lakera Guard returns only a detection decision (`flagged`); enforcing the
        # block/allow action is the policy's responsibility, so a flagged prompt counts
        # as blocked only when the collector targets a blocking Lakera policy.
        return Verdict(
            flagged=flagged,
            blocked=flagged and self.blocking_policy,
            detail=detail or "Lakera Guard flagged",
        )
