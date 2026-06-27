import datetime

from prisma_airs.client import PrismaAirsClient
from prisma_airs.configuration.config_loader import ConfigLoader
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from pyoaev.signatures.ai_marker import build_marker

DETECTION = "DETECTION"
PREVENTION = "PREVENTION"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class OpenAEVPrismaAirs(CollectorDaemon):
    """Validates Palo Alto Prisma AIRS detection/prevention of AI adversarial injects by replaying
    each inject's attack content through the Prisma AIRS Scan API."""

    def __init__(self, configuration: Configuration):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_prisma_airs",
        )
        self.collector_id = self._configuration.get("collector_id")
        self.client = PrismaAirsClient(
            {
                k: self._configuration.get(k)
                for k in ("prisma_base_url", "prisma_api_key", "prisma_ai_profile")
            },
            self.logger,
        )

    def _attack_for(self, expectation):
        inject_id = expectation.get("inject_expectation_inject")
        if not inject_id:
            return None
        try:
            inject = self.api.http_get(f"/injects/{inject_id}")
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(f"Could not fetch inject {inject_id}: {exc}")
            return None
        content = (inject or {}).get("inject_content") or {}
        prompt = content.get("attack_prompt")
        if not prompt:
            return None
        marker = build_marker(
            inject_id, expectation.get("inject_expectation_agent") or ""
        )
        return prompt.replace("{marker}", marker)

    def _process_message(self) -> None:
        expectations = self.api.inject_expectation.ai_expectations_for_source(
            self.collector_id
        )
        if not expectations:
            return
        traces = []
        verdicts = {}
        for expectation in expectations:
            inject_id = expectation.get("inject_expectation_inject")
            expectation_type = expectation.get("inject_expectation_type")
            if expectation_type not in (DETECTION, PREVENTION):
                continue
            if not inject_id:
                self.logger.warning(
                    "Skipping expectation "
                    f"{expectation.get('inject_expectation_id')} with no inject id"
                )
                continue
            if inject_id not in verdicts:
                prompt = self._attack_for(expectation)
                if not prompt:
                    verdicts[inject_id] = None
                else:
                    try:
                        verdicts[inject_id] = self.client.scan(prompt)
                    except Exception as exc:  # noqa: BLE001
                        self.logger.error(
                            f"Prisma AIRS scan failed for inject {inject_id}: {exc}"
                        )
                        verdicts[inject_id] = None
            verdict = verdicts[inject_id]
            if verdict is None:
                continue
            if expectation_type == DETECTION:
                is_success = verdict.flagged
                result = "Detected" if is_success else "Not Detected"
            else:
                is_success = verdict.blocked
                result = "Prevented" if is_success else "Not Prevented"
            self.api.inject_expectation.update(
                expectation["inject_expectation_id"],
                {
                    "collector_id": self.collector_id,
                    "result": result,
                    "is_success": is_success,
                    "metadata": {"detail": verdict.detail},
                },
            )
            if is_success:
                traces.append(
                    {
                        "inject_expectation_trace_expectation": expectation[
                            "inject_expectation_id"
                        ],
                        "inject_expectation_trace_source_id": self.collector_id,
                        "inject_expectation_trace_alert_name": verdict.detail
                        or "Prisma AIRS",
                        "inject_expectation_trace_alert_link": verdict.link or "",
                        "inject_expectation_trace_date": _now(),
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
    OpenAEVPrismaAirs(configuration=ConfigLoader().to_daemon_config()).start()
