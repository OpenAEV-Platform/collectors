"""A lab collector for the end-to-end tests: it answers each pending detection as
detected, with a trace."""

from unittest.mock import MagicMock

from collectors_sdk import CollectorDaemon
from xtm_oaev_sdk import Configuration

config = Configuration(
    config_hints={
        "collector_id": {"data": "lab-collector"},
        "collector_name": {"data": "Lab SIEM"},
        "collector_log_level": {"data": "error"},
        "collector_period": {"data": 60, "is_number": True},
        "collector_icon_filepath": {"data": __file__},
    }
)


def cycle(collector):
    for expectation in collector.api.inject_expectation.expectations_assets_for_source(
        "lab-collector"
    ):
        eid = expectation["inject_expectation_id"]
        ip = next(
            s["value"]
            for s in expectation["inject_expectation_signatures"]
            if s["type"] == "target_ipv4_address"
        )
        collector.api.inject_expectation.update(
            eid,
            inject_expectation={
                "collector_id": "lab-collector",
                "result": "Detected",
                "is_success": True,
                "metadata": {"ip": ip},
            },
        )
        collector.api.inject_expectation_trace.bulk_create(
            payload={
                "expectation_traces": [
                    {
                        "inject_expectation_trace_expectation": eid,
                        "inject_expectation_trace_source_id": "lab-collector",
                        "inject_expectation_trace_alert_name": f"Ping from {ip}",
                        "inject_expectation_trace_alert_link": "https://siem.invalid/a/1",
                        "inject_expectation_trace_date": "2026-11-10T08:00:00Z",
                    }
                ]
            }
        )


CollectorDaemon(
    configuration=config,
    callback=cycle,
    logger=MagicMock(),
    api_client=MagicMock(),
    collector_type="openaev_lab_siem",
).start()
