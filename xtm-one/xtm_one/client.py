"""Thin XTM One read client.

Reads the agents catalog (``GET /api/v1/agents``) and, optionally, the bare LLM
models exposed by the OpenAI-compatible proxy (``GET /v1/models``) so the
collector can mirror them as OpenAEV AI targets. It also reads the security
audit log (``GET /api/v1/audit-logs``) to surface the "Prompt injection
detected" events used to validate detection expectations. Only read operations
are performed here; nothing is ever written back to XTM One.
"""

from urllib.parse import urlparse

import requests

# Security audit-log filters (see XTM One ``GET /api/v1/audit-logs``).
SECURITY_ALERT_ACTION = "security_alert"
SECURITY_ENTITY_TYPE = "security"
# The audit-log endpoint caps ``limit`` at 200; page through it defensively so a
# single busy window cannot make the collector fetch unbounded history.
_AUDIT_PAGE_SIZE = 200
_AUDIT_MAX_PAGES = 50


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

    def _get(self, path: str, params: dict | None = None) -> object:
        resp = self.session.get(
            f"{self.base_url}{path}",
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def list_agents(self) -> list[dict]:
        """Return the chat-capable agents exposed by XTM One.

        Agents that are disabled, hidden from chat, or without a slug cannot be
        reached through the Platform Chat API, so they are filtered out.
        """
        self._validate()
        data = self._get("/api/v1/agents")
        if isinstance(data, list):
            agents = data
        elif isinstance(data, dict):
            agents = data.get("items", [])
        else:
            if self.logger:
                self.logger.warning(
                    f"Unexpected /api/v1/agents payload type {type(data).__name__}; "
                    "expected a list or an object with an 'items' key."
                )
            agents = []
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
            if not model_id or str(model_id).startswith("agent:"):
                continue
            if model.get("owned_by") == "copilot":
                continue
            result.append(model)
        return result

    def list_security_events(self, date_from: str | None = None) -> list[dict]:
        """Return XTM One security-alert audit events (prompt-injection detections).

        Pages through ``GET /api/v1/audit-logs`` scoped to
        ``action=security_alert`` and ``entity_type=security`` (newest first).
        ``date_from`` is an inclusive ISO-8601 lower bound on ``created_at`` used
        to only pull events since the oldest expectation still waiting.

        The audit-log API is admin-only, so the configured token
        (``xtm_one_token``) must belong to an XTM One administrator; otherwise
        the request fails with a 403.
        """
        self._validate()
        events: list[dict] = []
        offset = 0
        for _ in range(_AUDIT_MAX_PAGES):
            params = {
                "action": SECURITY_ALERT_ACTION,
                "entity_type": SECURITY_ENTITY_TYPE,
                "limit": _AUDIT_PAGE_SIZE,
                "offset": offset,
            }
            if date_from:
                params["date_from"] = date_from
            data = self._get("/api/v1/audit-logs", params=params)
            if isinstance(data, dict):
                items = data.get("items", [])
                total = data.get("total")
            elif isinstance(data, list):
                items = data
                total = None
            else:
                if self.logger:
                    self.logger.warning(
                        "Unexpected /api/v1/audit-logs payload type "
                        f"{type(data).__name__}; expected an object with an "
                        "'items' key."
                    )
                break
            events.extend(item for item in items if isinstance(item, dict))
            offset += _AUDIT_PAGE_SIZE
            if len(items) < _AUDIT_PAGE_SIZE:
                break
            if total is not None and offset >= total:
                break
        return events
