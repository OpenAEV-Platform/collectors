"""Thin XTM One read client.

Reads the agents catalog (``GET /api/v1/agents``) and, optionally, the bare LLM
models exposed by the OpenAI-compatible proxy (``GET /v1/models``) so the
collector can mirror them as OpenAEV AI targets. Only read operations are
performed here; nothing is ever written back to XTM One.
"""

from urllib.parse import urlparse

import requests


class XtmOneClient:
    def __init__(self, base_url: str | None, token: str | None, logger=None):
        self.base_url = (base_url or "").rstrip("/")
        self.token = token
        self.logger = logger
        self.session = requests.Session()

    def _validate(self) -> None:
        if not self.base_url:
            raise ValueError(
                "XTM One url is not configured; set collector.xtm_one_url "
                "(COLLECTOR_XTM_ONE_URL) to the XTM One base URL."
            )
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "XTM One url must be a valid http(s) URL including a host, e.g. "
                f"https://xtm-one.example.com; got {self.base_url!r}."
            )
        if not self.token:
            raise ValueError(
                "XTM One token is not configured; set collector.xtm_one_token "
                "(COLLECTOR_XTM_ONE_TOKEN) so the agents catalog can be read."
            )

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _get(self, path: str) -> object:
        resp = self.session.get(
            f"{self.base_url}{path}", headers=self._headers(), timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def list_agents(self) -> list[dict]:
        """Return the chat-capable agents exposed by XTM One.

        Agents that are disabled, hidden from chat, or without a slug cannot be
        reached through the OpenAI-compatible proxy, so they are filtered out.
        """
        self._validate()
        data = self._get("/api/v1/agents")
        agents = data if isinstance(data, list) else data.get("items", [])
        result = []
        for agent in agents:
            if not isinstance(agent, dict):
                continue
            if not agent.get("enabled", False):
                continue
            if agent.get("disable_chat", False):
                continue
            slug = agent.get("slug")
            if not slug:
                continue
            result.append(agent)
        return result

    def list_bare_models(self) -> list[dict]:
        """Return the bare LLM models exposed by the OpenAI-compatible proxy.

        Agents are surfaced by ``/v1/models`` as ``agent:<slug>`` entries owned
        by ``copilot``; those are excluded here since agents are collected from
        the dedicated agents endpoint.
        """
        self._validate()
        data = self._get("/v1/models")
        models = data.get("data", []) if isinstance(data, dict) else []
        result = []
        for model in models:
            if not isinstance(model, dict):
                continue
            model_id = model.get("id")
            if not model_id or model_id.startswith("agent:"):
                continue
            if model.get("owned_by") == "copilot":
                continue
            result.append(model)
        return result
