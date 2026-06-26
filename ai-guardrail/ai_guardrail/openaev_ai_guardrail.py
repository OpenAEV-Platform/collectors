from ai_guardrail.clients import GuardrailClient
from ai_guardrail.configuration.config_loader import ConfigLoader
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from pyoaev.signatures.ai_marker import build_marker
from pyoaev.signatures.types import SignatureTypes

DETECTION = "DETECTION"
PREVENTION = "PREVENTION"


class OpenAEVAiGuardrail(CollectorDaemon):
    """Validates that an AI defense (LLM firewall / guardrail / AI gateway) detected or prevented
    AI adversarial injects, by correlating the per-inject canary marker against the guardrail's logged
    decisions, and fills the DETECTION / PREVENTION expectations accordingly."""

    def __init__(self, configuration: Configuration):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_ai_guardrail",
        )
        self.collector_id = self._configuration.get("collector_id")
        client_config = {
            key: self._configuration.get(key)
            for key in (
                "guardrail_provider",
                "guardrail_events_url",
                "guardrail_api_key",
                "guardrail_marker_param",
                "guardrail_flagged_field",
                "guardrail_blocked_field",
                "guardrail_lookback_minutes",
            )
        }
        self.client = GuardrailClient(client_config, self.logger)

    def _marker_for(self, expectation: dict) -> str:
        # Prefer an explicit marker signature if the platform generated one; otherwise derive it
        # deterministically from the inject (+ agent) id - identical to the injector's algorithm.
        for signature in expectation.get("inject_expectation_signatures") or []:
            if signature.get("type") == SignatureTypes.SIG_TYPE_AI_REQUEST_MARKER.value:
                return signature.get("value")
        inject_id = expectation.get("inject_expectation_inject")
        agent_id = expectation.get("inject_expectation_agent") or ""
        return build_marker(inject_id, agent_id)

    def _process_message(self) -> None:
        expectations = self.api.inject_expectation.ai_expectations_for_source(self.collector_id)
        if not expectations:
            return
        traces = []
        for expectation in expectations:
            expectation_id = expectation.get("inject_expectation_id")
            expectation_type = expectation.get("inject_expectation_type")
            marker = self._marker_for(expectation)
            if not marker:
                continue
            events = self.client.fetch_events(marker)
            flagged = any(event.flagged for event in events)
            blocked = any(event.blocked for event in events)

            if expectation_type == DETECTION:
                is_success = flagged
                result = "Detected" if is_success else "Not Detected"
            elif expectation_type == PREVENTION:
                is_success = blocked
                result = "Prevented" if is_success else "Not Prevented"
            else:
                continue

            self.api.inject_expectation.update(
                expectation_id,
                {
                    "collector_id": self.collector_id,
                    "result": result,
                    "is_success": is_success,
                    "metadata": {"marker": marker, "events": len(events)},
                },
            )
            for event in events:
                if event.flagged or event.blocked:
                    traces.append(
                        {
                            "inject_expectation_trace_expectation": expectation_id,
                            "inject_expectation_trace_source_id": self.collector_id,
                            "inject_expectation_trace_alert_name": event.name,
                            "inject_expectation_trace_alert_link": event.link,
                            "inject_expectation_trace_date": event.date,
                        }
                    )

        if traces:
            try:
                self.api.inject_expectation_trace.bulk_create(
                    payload={"expectation_traces": traces}
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(f"Could not create expectation traces: {exc}")


if __name__ == "__main__":
    OpenAEVAiGuardrail(configuration=ConfigLoader().to_daemon_config()).start()
