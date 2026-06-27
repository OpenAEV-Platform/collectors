"""Palo Alto Prisma AIRS (AI Runtime Security) client.

Replays an AI red-team inject's attack content through the Prisma AIRS Scan API and reads the
verdict/action, validating whether the configured AI security profile detects / blocks the attack.

Docs: https://pan.dev/prisma-airs/api/airuntimesecurity/
Scan API: POST {base_url}/v1/scan/sync/request, header x-pan-token, payload carries ai_profile.
"""

import uuid

import requests


class Verdict:
    def __init__(self, flagged: bool, blocked: bool, detail: str = "", link: str = ""):
        self.flagged = flagged
        self.blocked = blocked
        self.detail = detail
        self.link = link


class PrismaAirsClient:
    def __init__(self, config: dict, logger=None):
        # Region-specific base URL (US default). EU: service-de..., IN: service-in..., SG: service-sg...
        self.base_url = (
            config.get("prisma_base_url")
            or "https://service.api.aisecurity.paloaltonetworks.com"
        ).rstrip("/")
        self.api_key = config.get("prisma_api_key")
        self.profile_name = config.get("prisma_ai_profile")
        self.logger = logger
        self.session = requests.Session()

    def scan(self, prompt: str, system_prompt: str | None = None) -> Verdict:
        if not self.api_key or not self.profile_name:
            raise ValueError(
                "Prisma AIRS is not fully configured: both api_key and ai_profile "
                "are required (set COLLECTOR_API_KEY and COLLECTOR_AI_PROFILE)."
            )
        headers = {"x-pan-token": self.api_key, "Content-Type": "application/json"}
        body = {
            "tr_id": str(uuid.uuid4()),
            "ai_profile": {"profile_name": self.profile_name},
            "contents": [{"prompt": prompt}],
        }
        resp = self.session.post(
            f"{self.base_url}/v1/scan/sync/request",
            headers=headers,
            json=body,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        action = str(data.get("action", "")).lower()
        category = str(data.get("category", "")).lower()
        prompt_detected = data.get("prompt_detected") or {}
        detected = category == "malicious" or any(
            bool(v) for v in prompt_detected.values()
        )
        flagged = detected or action == "block"
        blocked = action == "block"
        detail = ", ".join(k for k, v in prompt_detected.items() if v) or (
            category or "Prisma AIRS scan"
        )
        return Verdict(flagged=flagged, blocked=blocked, detail=detail)
