"""Guardrail event clients.

An AI defense (LLM firewall / guardrail / AI gateway) sits in front of the model. The ai-redteam
injector tags every request with a per-inject canary marker (`X-OAEV-Inject-Marker`). The guardrail
logs its decision for that request; this client retrieves those decisions by marker so the collector
can fill the DETECTION (flagged) and PREVENTION (blocked) expectations.

A single, configurable HTTP client covers the supported providers (generic / Lakera / NeMo); the
`provider` only changes sensible defaults. Any gateway that exposes decisions queryable by the marker
works with the `generic` provider.
"""

import datetime

import requests


class GuardrailEvent:
    def __init__(self, flagged: bool, blocked: bool, name: str, link: str = "", date: str = ""):
        self.flagged = flagged
        self.blocked = blocked
        self.name = name
        self.link = link
        self.date = date or datetime.datetime.now(datetime.timezone.utc).isoformat()


class GuardrailClient:
    def __init__(self, config: dict, logger=None):
        self.provider = (config.get("guardrail_provider") or "generic").lower()
        self.events_url = config.get("guardrail_events_url")
        self.api_key = config.get("guardrail_api_key")
        self.marker_param = config.get("guardrail_marker_param") or "marker"
        self.flagged_field = config.get("guardrail_flagged_field") or "flagged"
        self.blocked_field = config.get("guardrail_blocked_field") or "blocked"
        self.lookback_minutes = int(config.get("guardrail_lookback_minutes") or 60)
        self.logger = logger
        self.session = requests.Session()

    def _headers(self):
        headers = {"Accept": "application/json"}
        if self.api_key:
            if self.provider == "lakera":
                headers["Authorization"] = f"Bearer {self.api_key}"
            else:
                headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def fetch_events(self, marker: str):
        """Return the list of GuardrailEvent logged for the given inject marker."""
        if not self.events_url:
            if self.logger:
                self.logger.warning(
                    "No guardrail events_url configured; cannot validate AI defense decisions."
                )
            return []
        since = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=self.lookback_minutes)
        ).isoformat()
        params = {self.marker_param: marker, "since": since}
        try:
            resp = self.session.get(
                self.events_url, headers=self._headers(), params=params, timeout=30
            )
        except requests.RequestException as exc:
            if self.logger:
                self.logger.error(f"Guardrail events query failed: {exc}")
            return []
        return self._parse(resp, marker)

    def _parse(self, resp, marker):
        events = []
        try:
            data = resp.json()
        except ValueError:
            return events
        rows = data
        if isinstance(data, dict):
            rows = data.get("events") or data.get("results") or data.get("data") or []
        if not isinstance(rows, list):
            return events
        for row in rows:
            if not isinstance(row, dict):
                continue
            flagged = self._provider_flagged(row)
            blocked = self._provider_blocked(row)
            name = row.get("name") or row.get("detector") or f"{self.provider} guardrail decision"
            link = row.get("link") or row.get("url") or ""
            date = row.get("date") or row.get("created_at") or ""
            events.append(GuardrailEvent(flagged, blocked, name, link, date))
        return events

    def _provider_flagged(self, row: dict) -> bool:
        if self.provider == "lakera":
            # Lakera Guard marks a request with flagged categories / a top-level flagged bool
            if isinstance(row.get("flagged"), bool):
                return row["flagged"]
            results = row.get("results") or row.get("categories") or {}
            if isinstance(results, dict):
                return any(bool(v) for v in results.values())
            return bool(results)
        if self.provider == "nemo":
            # NeMo Guardrails: a triggered input/output rail (e.g. blocked or 'refuse' action)
            return bool(row.get("flagged") or row.get("triggered") or row.get("blocked"))
        return bool(row.get(self.flagged_field))

    def _provider_blocked(self, row: dict) -> bool:
        if self.provider == "nemo":
            action = (row.get("action") or "").lower()
            return bool(row.get("blocked")) or action in ("block", "refuse", "reject")
        if self.provider == "lakera":
            return bool(row.get("blocked"))
        return bool(row.get(self.blocked_field))
