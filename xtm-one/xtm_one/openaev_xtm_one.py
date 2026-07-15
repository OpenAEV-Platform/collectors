"""Import XTM One agents as OpenAEV AI targets and validate AI defense expectations.

The collector has two complementary jobs. Import runs on every scheduled cycle;
validation also runs each cycle unless disabled with ``validate_expectations``:

1. **Import** - it reads the XTM One agents catalog (optionally scoped to a set
   of tags) and upserts one OpenAEV ``AiTarget`` per agent. Each agent target
   carries the ``XTM_ONE`` provider, the XTM One base URL as
   ``ai_target_endpoint`` and ``agent:<slug>`` as ``ai_target_model``; the AI
   red team injector derives the agent slug from that recorded model and calls
   ``{endpoint}/api/v1/platform/chat/messages`` itself. Agents go through the
   Platform Chat API rather than the OpenAI-compatible ``/v1`` proxy, because
   that proxy is disabled when XTM One runs in ``xtm_one`` platform mode. When
   ``include_bare_models`` is enabled it additionally mirrors the bare LLM models
   exposed by the OpenAI-compatible proxy. Targets are matched on a stable
   external reference so the collector is idempotent.

2. **Validate** - like an EDR/AI-defense collector, it fulfills the DETECTION and
   PREVENTION expectations raised by the AI red team injector. It reads XTM One's
   security audit log (``GET /api/v1/audit-logs``) and correlates each
   "Prompt injection detected" event back to the inject that triggered it using
   the per-inject canary marker embedded in the attack prompt (the same
   ``oaev<sha>`` token the injector and platform derive from the inject id). A
   matching event fulfills DETECTION as *Detected*. XTM One's authenticated agent
   chat only detects and logs prompt injections (it does not block the request),
   so PREVENTION is reported as *Not Prevented*; ``_is_prevented`` centralizes
   that decision so it can flip to true if XTM One later records a blocking
   signal. Expectations with no matching event by the time they expire are failed
   (*Not Detected* / *Not Prevented*). Set ``validate_expectations`` to false to
   run the collector as a pure importer.

The XTM One API key from the collector config (``xtm_one_token``) is written onto
each AI target (``ai_target_token``) so the injector can authenticate to XTM One
directly, and is also used to read the agents catalog and the audit log (the
latter requires the key to belong to an XTM One administrator).
"""

from datetime import datetime, timedelta, timezone

from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from pyoaev.signatures.ai_marker import build_marker
from xtm_one.client import XtmOneClient
from xtm_one.configuration.config_loader import ConfigLoader

# Agents are called through the dedicated XTM One provider (Platform Chat API);
# bare LLM models are only reachable through the OpenAI-compatible proxy.
AGENT_PROVIDER = "XTM_ONE"
MODEL_PROVIDER = "OPENAI_COMPATIBLE"
SOURCE_TAG = "source:xtm-one"
AGENT_TAG = "type:agent"
MODEL_TAG = "type:model"
SOURCE_TAG_COLOR = "#0ea5e9"
KIND_TAG_COLOR = "#6366f1"

# Expectation validation.
DETECTION = "DETECTION"
PREVENTION = "PREVENTION"
DETECTED = "Detected"
NOT_DETECTED = "Not Detected"
PREVENTED = "Prevented"
NOT_PREVENTED = "Not Prevented"
# Signature attached to AI expectations that carries the per-inject canary marker.
AI_REQUEST_MARKER_SIGNATURE = "ai_request_marker"
# Widen the audit-log window slightly around the expectation dates to absorb any
# clock skew between the collector, OpenAEV and XTM One.
_EVENT_WINDOW_BUFFER = timedelta(minutes=5)
# Fallback lookback when an expectation is missing its creation date (should not
# happen in practice, since OpenAEV always sets it).
_EVENT_LOOKBACK_FALLBACK = timedelta(hours=24)


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into a timezone-aware datetime.

    Naive timestamps are assumed to be UTC; explicit offsets are preserved
    as-is (aware datetimes compare correctly across offsets).
    """
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class OpenAEVXtmOne(CollectorDaemon):
    def __init__(self, configuration: Configuration):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_xtm_one",
        )
        self.collector_id = self._configuration.get("collector_id")
        self.xtm_one_url = (self._configuration.get("xtm_one_url") or "").rstrip("/")
        self.xtm_one_token = self._configuration.get("xtm_one_token")
        self.include_bare_models = bool(self._configuration.get("include_bare_models"))
        self.validate_expectations = bool(
            self._configuration.get("validate_expectations")
        )
        self.agent_tags = self._parse_tags(self._configuration.get("agent_tags"))
        self.client = XtmOneClient(
            self.xtm_one_url,
            self.xtm_one_token,
            self.logger,
        )
        self._tag_cache: dict[str, str] = {}

    @staticmethod
    def _parse_tags(raw) -> set[str]:
        if not raw:
            return set()
        return {t.strip().lower() for t in str(raw).split(",") if t.strip()}

    @property
    def _agent_endpoint(self) -> str:
        """XTM One base URL; the AI red team injector's ``XTM_ONE`` provider
        appends ``/api/v1/platform/chat/messages`` itself."""
        return self.xtm_one_url

    @property
    def _model_endpoint(self) -> str:
        """OpenAI-compatible proxy base; the AI red team injector appends
        ``/chat/completions`` itself."""
        return f"{self.xtm_one_url}/v1"

    def _resolve_tag(self, name: str, color: str) -> str | None:
        if name in self._tag_cache:
            return self._tag_cache[name]
        try:
            result = self.api.tag.upsert({"tag_name": name, "tag_color": color})
            tag_id = result.get("tag_id")
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(f"Failed to upsert tag {name}: {exc}")
            return None
        if tag_id:
            self._tag_cache[name] = tag_id
        return tag_id

    def _resolve_tags(self, names: list[str]) -> list[str]:
        ids = []
        for name in names:
            color = SOURCE_TAG_COLOR if name == SOURCE_TAG else KIND_TAG_COLOR
            tag_id = self._resolve_tag(name, color)
            if tag_id:
                ids.append(tag_id)
        return ids

    def _agent_in_scope(self, agent: dict) -> bool:
        if not self.agent_tags:
            return True
        agent_tags = {str(t).strip().lower() for t in (agent.get("tags") or [])}
        return bool(agent_tags & self.agent_tags)

    def _agent_payload(self, agent: dict) -> dict:
        slug = agent.get("slug")
        name = agent.get("name") or slug
        # Normalize mirrored tags the same way scoping does, so inconsistent
        # casing/whitespace in XTM One never creates duplicate OpenAEV tags.
        agent_tags = sorted(
            {
                str(t).strip().lower()
                for t in (agent.get("tags") or [])
                if str(t).strip()
            }
        )
        tag_ids = self._resolve_tags([SOURCE_TAG, AGENT_TAG] + agent_tags)
        return {
            "asset_name": f"{name} (XTM One agent)",
            "asset_description": agent.get("description")
            or "XTM One agent reached through the Platform Chat API.",
            "asset_external_reference": f"xtm-one:agent:{slug}",
            "asset_tags": tag_ids,
            "ai_target_provider": AGENT_PROVIDER,
            "ai_target_endpoint": self._agent_endpoint,
            "ai_target_model": f"agent:{slug}",
            "ai_target_modality": "TEXT",
            "ai_target_token": self.xtm_one_token,
            "ai_target_configuration": {
                "source": "xtm-one",
                "xtm_one_kind": "agent",
                "xtm_one_slug": slug,
            },
        }

    def _model_payload(self, model: dict) -> dict:
        model_id = model.get("id")
        tag_ids = self._resolve_tags([SOURCE_TAG, MODEL_TAG])
        return {
            "asset_name": f"{model_id} (XTM One model)",
            "asset_description": "Bare LLM model exposed through the XTM One "
            "OpenAI-compatible proxy.",
            "asset_external_reference": f"xtm-one:model:{model_id}",
            "asset_tags": tag_ids,
            "ai_target_provider": MODEL_PROVIDER,
            "ai_target_endpoint": self._model_endpoint,
            "ai_target_model": model_id,
            "ai_target_modality": "TEXT",
            "ai_target_token": self.xtm_one_token,
            "ai_target_configuration": {
                "source": "xtm-one",
                "xtm_one_kind": "model",
                "xtm_one_model": model_id,
            },
        }

    def _existing_targets(self) -> dict[str, str]:
        """Map ``asset_external_reference`` -> ``asset_id`` for previously
        imported targets so runs are idempotent."""
        mapping: dict[str, str] = {}
        try:
            targets = self.api.ai_target.list()
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(f"Could not list existing AI targets: {exc}")
            return mapping
        for target in targets:
            ref = getattr(target, "asset_external_reference", None)
            asset_id = getattr(target, "asset_id", None)
            if ref and asset_id and str(ref).startswith("xtm-one:"):
                mapping[ref] = asset_id
        return mapping

    def _upsert(self, payload: dict, existing: dict[str, str]) -> None:
        ref = payload["asset_external_reference"]
        try:
            if ref in existing:
                self.api.ai_target.update(existing[ref], payload)
                self.logger.info(f"Updated AI target {ref}")
            else:
                self.api.ai_target.create(payload)
                self.logger.info(f"Created AI target {ref}")
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Failed to upsert AI target {ref}: {exc}")

    def _import_targets(self) -> None:
        """Mirror the XTM One agents (and optional bare models) as AI targets."""
        try:
            agents = self.client.list_agents()
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Could not fetch XTM One agents: {exc}")
            return

        existing = self._existing_targets()

        for agent in agents:
            if not self._agent_in_scope(agent):
                continue
            self._upsert(self._agent_payload(agent), existing)

        if self.include_bare_models:
            try:
                models = self.client.list_bare_models()
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"Could not fetch XTM One models: {exc}")
                models = []
            for model in models:
                self._upsert(self._model_payload(model), existing)

    # -- Expectation validation ------------------------------------------------

    @staticmethod
    def _marker_for(expectation: dict, inject_id: str) -> str | None:
        """Return the canary marker correlating this expectation to a XTM One event.

        Prefer the ``ai_request_marker`` signature the platform attaches to the
        expectation; fall back to recomputing it from the inject id so the
        collector stays compatible with expectations created before signatures
        were populated. Both paths yield the same ``oaev<sha>`` value the
        injector embeds in the attack prompt.
        """
        for signature in expectation.get("inject_expectation_signatures") or []:
            if (
                isinstance(signature, dict)
                and signature.get("type") == AI_REQUEST_MARKER_SIGNATURE
                and signature.get("value")
            ):
                return str(signature["value"])
        if not inject_id:
            return None
        return build_marker(
            inject_id, expectation.get("inject_expectation_agent") or ""
        )

    @staticmethod
    def _event_matches(marker: str, event: dict) -> bool:
        details = event.get("details") or {}
        preview = details.get("message_preview") or ""
        return bool(marker) and marker in preview

    @staticmethod
    def _is_prevented(event: dict) -> bool:
        """Whether the security event proves the attack was blocked, not just seen.

        XTM One's authenticated agent chat detects prompt injections but keeps
        processing the request (detect-and-continue), so today a logged event
        never means prevention. This hook honors an explicit blocking signal if
        XTM One ever starts recording one, keeping the rest of the pipeline
        untouched.
        """
        details = event.get("details") or {}
        if details.get("blocked") is True or details.get("prevented") is True:
            return True
        outcome = str(details.get("action") or details.get("outcome") or "").lower()
        return outcome in ("blocked", "prevented", "reject", "rejected")

    def _event_window_start(self, expectations: list[dict]) -> str:
        """Lower bound for the audit-log query: just before the oldest expectation."""
        created = []
        for expectation in expectations:
            raw = expectation.get("inject_expectation_created_at")
            if raw:
                try:
                    created.append(_parse_iso(raw))
                except (ValueError, TypeError):
                    continue
        if created:
            start = min(created) - _EVENT_WINDOW_BUFFER
        else:
            start = datetime.now(timezone.utc) - _EVENT_LOOKBACK_FALLBACK
        return start.isoformat()

    def _is_expired(self, expectation: dict, now: datetime) -> bool:
        raw_created = expectation.get("inject_expectation_created_at")
        expiration = expectation.get("inject_expiration_time")
        if not raw_created or expiration is None:
            return False
        try:
            deadline = _parse_iso(raw_created) + timedelta(seconds=int(expiration))
        except (ValueError, TypeError):
            return False
        return deadline < now

    def _update_expectation(
        self, expectation_id: str, result: str, is_success: bool, metadata: dict
    ) -> None:
        try:
            self.api.inject_expectation.update(
                expectation_id,
                {
                    "collector_id": self.collector_id,
                    "result": result,
                    "is_success": is_success,
                    "metadata": metadata,
                },
            )
            self.logger.info(
                f"Expectation {expectation_id} -> {result} (success={is_success})"
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Failed to update expectation {expectation_id}: {exc}")

    def _fulfill(
        self, expectation: dict, expectation_type: str, event: dict
    ) -> dict | None:
        """Fill a matched expectation and return a trace when it is a success."""
        expectation_id = expectation["inject_expectation_id"]
        details = event.get("details") or {}
        metadata = {
            "audit_log_id": event.get("id"),
            "agent_slug": details.get("agent_slug"),
            "agent_name": details.get("agent_name") or event.get("entity_name"),
            "conversation_id": details.get("conversation_id"),
            "severity": details.get("severity"),
            "reasons": details.get("reasons"),
        }
        if expectation_type == DETECTION:
            result, is_success = DETECTED, True
        else:
            prevented = self._is_prevented(event)
            result, is_success = (
                (PREVENTED, True) if prevented else (NOT_PREVENTED, False)
            )
        self._update_expectation(expectation_id, result, is_success, metadata)
        if not is_success:
            return None
        return {
            "inject_expectation_trace_expectation": expectation_id,
            "inject_expectation_trace_source_id": self.collector_id,
            "inject_expectation_trace_alert_name": event.get("summary")
            or "Prompt injection detected",
            "inject_expectation_trace_alert_link": self.xtm_one_url,
            "inject_expectation_trace_date": event.get("created_at")
            or datetime.now(timezone.utc).isoformat(),
        }

    def _validate_expectations(self) -> None:
        try:
            expectations = self.api.inject_expectation.ai_expectations_for_source(
                self.collector_id
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Could not fetch AI expectations: {exc}")
            return

        pending = [
            expectation
            for expectation in (expectations or [])
            if expectation.get("inject_expectation_inject")
            and expectation.get("inject_expectation_type") in (DETECTION, PREVENTION)
        ]
        if not pending:
            self.logger.info("No AI expectations waiting to be matched")
            return

        try:
            events = self.client.list_security_events(
                date_from=self._event_window_start(pending)
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Could not fetch XTM One security events: {exc}")
            return

        self.logger.info(
            f"Matching {len(pending)} AI expectation(s) against "
            f"{len(events)} XTM One security event(s)"
        )

        now = datetime.now(timezone.utc)
        traces = []
        for expectation in pending:
            expectation_type = expectation["inject_expectation_type"]
            marker = self._marker_for(
                expectation, expectation["inject_expectation_inject"]
            )
            event = None
            if marker:
                event = next(
                    (e for e in events if self._event_matches(marker, e)), None
                )
            if event is not None:
                trace = self._fulfill(expectation, expectation_type, event)
                if trace:
                    traces.append(trace)
            elif self._is_expired(expectation, now):
                result = (
                    NOT_DETECTED if expectation_type == DETECTION else NOT_PREVENTED
                )
                self._update_expectation(
                    expectation["inject_expectation_id"],
                    result,
                    False,
                    {"reason": "expired: no matching XTM One security event"},
                )
            # Otherwise leave it pending for a later cycle.

        if traces:
            try:
                self.api.inject_expectation_trace.bulk_create(
                    payload={"expectation_traces": traces}
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(f"Could not create expectation traces: {exc}")

    def _process_message(self) -> None:
        self._import_targets()
        if self.validate_expectations:
            self._validate_expectations()


if __name__ == "__main__":
    OpenAEVXtmOne(configuration=ConfigLoader().to_daemon_config()).start()
