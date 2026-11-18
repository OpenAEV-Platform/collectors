"""Tests for running a collector without the platform (dev mode).

Feature: Run a collector without the platform
  Started with --dev, a collector reads its pending expectations from --expectations
  (a file, or - for stdin) holding exactly what the platform serves: a JSON list of
  InjectExpectationOutput, as an injector's --emit expectations writes it. It never
  builds the platform client, never starts its heartbeat, and writes every update and
  trace it would have sent, as one JSON list of {"method", "path", "body"}, to --out. --once runs
  a single cycle.
"""

import io
import json
import sys
import threading
from pathlib import Path
from typing import Any, Callable, NamedTuple
from unittest.mock import MagicMock, patch

import pytest
from collectors_sdk import (
    CollectorDaemon,
    DetectionExpectation,
    PreventionExpectation,
    expectations_models_for_source,
)
from xtm_oaev_sdk import Configuration, NeedsPlatformError

COLLECTOR_ID = "c0ffee00-0000-4000-8000-000000000001"
DETECTION_ID = "4e5d0000-0000-4000-8000-00000000000d"
PREVENTION_ID = "4e5d0000-0000-4000-8000-00000000000e"


class Run(NamedTuple):
    exit_code: Any
    requests: list[dict[str, Any]]
    written: str
    stderr: str
    client_built: bool
    heartbeat: MagicMock
    seen: dict[str, Any]


class _RecordingCollector(CollectorDaemon):
    client_built = False

    def _create_default_api_client(self):
        _RecordingCollector.client_built = True
        return MagicMock()


def _pending(expectation_id: str, kind: str) -> dict[str, Any]:
    return {
        "inject_expectation_id": expectation_id,
        "inject_expectation_type": kind,
        "inject_expectation_name": kind.title(),
        "inject_expectation_description": None,
        "inject_expectation_score": None,
        "inject_expectation_expected_score": 100.0,
        "inject_expiration_time": 21600,
        "inject_expectation_group": False,
        "inject_expectation_order": None,
        "inject_expectation_status": "PENDING",
        "inject_expectation_created_at": "2026-11-05T20:00:00Z",
        "inject_expectation_updated_at": "2026-11-05T20:00:00Z",
        "inject_expectation_signatures": [
            {"type": "target_ipv4_address", "value": "127.0.0.1"}
        ],
        "inject_expectation_results": [],
        "inject_expectation_traces": [],
        "inject_expectation_exercise": None,
        "inject_expectation_inject": "8a4f1f0e-2c4b-4f43-9d5e-0b6f5b6f1a01",
        "inject_expectation_user": None,
        "inject_expectation_team": None,
        "inject_expectation_agent": None,
        "inject_expectation_asset": "0d3f7d1a-lab-1",
        "inject_expectation_asset_group": None,
        "inject_expectation_article": None,
        "inject_expectation_challenge": None,
        "target_id": "0d3f7d1a-lab-1",
        "inject_expectation_expected_security_platforms": None,
        "inject_expectation_collector_missing_at_init": False,
    }


def _given_pending_expectations() -> list[dict[str, Any]]:
    """Given the platform's pending expectations: one detection and one prevention"""
    return [
        _pending(DETECTION_ID, "DETECTION"),
        _pending(PREVENTION_ID, "PREVENTION"),
    ]


def _given_expectations_file(tmp_path: Path, feed: Any) -> str:
    """Given those pending expectations saved to a file"""
    path = tmp_path / "expectations.json"
    path.write_text(feed if isinstance(feed, str) else json.dumps(feed))
    return str(path)


def _given_collector_configuration(tmp_path: Path, **hints: Any) -> Configuration:
    """Given a SIEM collector configuration"""
    icon = tmp_path / "icon.png"
    icon.write_bytes(b"\x89PNG")
    config_hints = {
        "collector_id": {"data": COLLECTOR_ID},
        "collector_name": {"data": "Lab SIEM"},
        "collector_icon_filepath": {"data": str(icon)},
        "collector_period": {"data": 60},
        "collector_log_level": {"data": "info"},
    }
    config_hints.update({key: {"data": value} for key, value in hints.items()})
    return Configuration(config_hints=config_hints)


def _given_collector_reading(read: str) -> Callable[..., None]:
    """Given a collector whose cycle reads "<read>" from the platform client"""

    def cycle(collector: Any, seen: dict[str, Any]) -> None:
        manager = collector.api.inject_expectation
        if read == "models":
            seen["models"] = expectations_models_for_source(
                manager, source_id=COLLECTOR_ID
            )
        else:
            seen.setdefault(read, []).append(
                getattr(manager, read)(source_id=COLLECTOR_ID)
            )

    return cycle


def _given_collector_answering(*answers: tuple[str, bool]) -> Callable[..., None]:
    """Given a collector whose cycle answers <answers> and traces each detection"""

    def cycle(collector: Any, seen: dict[str, Any]) -> None:
        manager = collector.api.inject_expectation
        for expectation_id, success in answers:
            manager.update(
                expectation_id,
                inject_expectation={
                    "collector_id": COLLECTOR_ID,
                    "result": "Detected" if success else "Not Detected",
                    "is_success": success,
                    "metadata": {"alertId": "a-42"},
                },
            )
        seen["after"] = manager.expectations_assets_for_source(source_id=COLLECTOR_ID)

    return cycle


def _given_collector_bulk_answering() -> Callable[..., None]:
    """Given a collector whose cycle answers both expectations at once, then traces
    the detection"""

    def cycle(collector: Any, seen: dict[str, Any]) -> None:
        collector.api.inject_expectation.bulk_update(
            {
                DETECTION_ID: {"collector_id": COLLECTOR_ID, "is_success": True},
                PREVENTION_ID: {"collector_id": COLLECTOR_ID, "is_success": False},
            }
        )
        collector.api.inject_expectation_trace.bulk_create(
            payload={
                "expectation_traces": [
                    {
                        "inject_expectation_trace_expectation": DETECTION_ID,
                        "inject_expectation_trace_source_id": COLLECTOR_ID,
                        "inject_expectation_trace_alert_name": "Port scan",
                        "inject_expectation_trace_alert_link": "https://siem/a-42",
                        "inject_expectation_trace_date": "2026-11-05T20:01:00Z",
                    }
                ]
            }
        )

    return cycle


def _given_collector_sending_an_invalid_update() -> Callable[..., None]:
    """Given a collector whose cycle sends an update without its collector id"""

    def cycle(collector: Any, seen: dict[str, Any]) -> None:
        try:
            collector.api.inject_expectation.update(
                DETECTION_ID, inject_expectation={"is_success": True}
            )
        except Exception as error:  # noqa: BLE001
            seen["error"] = error

    return cycle


def _given_collector_calling_the_platform() -> Callable[..., None]:
    """Given a collector whose cycle upserts a payload on the platform"""

    def cycle(collector: Any, seen: dict[str, Any]) -> None:
        try:
            collector.api.payload.upsert({"payload_name": "lab"})
        except Exception as error:  # noqa: BLE001
            seen["error"] = error

    return cycle


def _given_collector_leaking(secret: str) -> Callable[..., None]:
    """Given a collector whose update metadata contains that secret"""

    def cycle(collector: Any, seen: dict[str, Any]) -> None:
        collector.api.inject_expectation.update(
            DETECTION_ID,
            inject_expectation={
                "collector_id": COLLECTOR_ID,
                "is_success": True,
                "metadata": {"query": f"search token={secret}"},
            },
        )

    return cycle


def _when_running_in_dev_mode(
    tmp_path: Path,
    cycle: Callable[..., None],
    *args: str,
    configuration: Configuration | None = None,
    stdin: str | None = None,
) -> Run:
    """When the collector starts with "--dev <args> --once --out run.json" """
    out = tmp_path / "run.json"
    argv = ["openaev-lab-siem", "--dev", *args, "--once", "--out", str(out)]
    seen: dict[str, Any] = {"cycles": 0}
    stderr = io.StringIO()
    _RecordingCollector.client_built = False
    config = configuration or _given_collector_configuration(tmp_path)
    with (
        patch.object(sys, "argv", argv),
        patch.object(sys, "stdin", io.StringIO(stdin or "")),
        patch.object(sys, "stderr", stderr),
        patch("xtm_oaev_sdk.PingAlive.start") as heartbeat,
    ):
        holder: dict[str, Any] = {"exit_code": "never returned"}

        def callback() -> None:
            seen["cycles"] += 1
            cycle(holder["collector"], seen)

        def start() -> None:
            try:
                holder["collector"] = _RecordingCollector(
                    configuration=config,
                    callback=callback,
                    logger=MagicMock(),
                    collector_type="openaev_lab_siem",
                )
                holder["collector"].start()
                holder["exit_code"] = None
            except SystemExit as exit_:
                holder["exit_code"] = exit_.code

        # A collector that never returns is a finding, not a hung test run.
        runner = threading.Thread(target=start, daemon=True)
        runner.start()
        runner.join(timeout=3)
        exit_code = holder["exit_code"]
    written = out.read_text() if out.exists() else ""
    requests = json.loads(written) if written else []
    return Run(
        exit_code,
        requests,
        written,
        stderr.getvalue(),
        _RecordingCollector.client_built,
        heartbeat,
        seen,
    )


def _when_building_the_collector_without_dev(
    tmp_path: Path,
) -> tuple[bool, MagicMock]:
    """When the collector is built and set up without "--dev" """
    _RecordingCollector.client_built = False
    with (
        patch.object(sys, "argv", ["openaev-lab-siem"]),
        patch("xtm_oaev_sdk.PingAlive.start") as heartbeat,
    ):
        collector = _RecordingCollector(
            configuration=_given_collector_configuration(tmp_path),
            callback=MagicMock(),
            logger=MagicMock(),
            collector_type="openaev_lab_siem",
        )
        collector._setup()
    return _RecordingCollector.client_built, heartbeat


def _then_platform_client_is_never_built(run: Run) -> None:
    """Then the platform client is never built"""
    assert run.client_built is False


def _then_heartbeat_never_starts(run: Run) -> None:
    """Then the heartbeat never starts"""
    run.heartbeat.assert_not_called()


def _then_collector_reads(run: Run, read: str, feed: list[dict[str, Any]]) -> None:
    """Then "<read>" returns exactly those pending expectations"""
    assert run.seen.get(read) == [feed]


def _then_models_are(run: Run, *expected: tuple[type, str]) -> None:
    """Then the expectation models are exactly <expected>"""
    models = run.seen.get("models")
    assert models is not None, "Expected the collector to build models"
    assert [(type(m), str(m.inject_expectation_id)) for m in models] == list(expected)


def _then_requests_are(run: Run, *expected: tuple[str, str]) -> None:
    """Then the calls written are exactly "<method> <path>" """
    assert [(r["method"], r["path"]) for r in run.requests] == list(expected)


def _then_request_body_is(run: Run, index: int, body: dict[str, Any]) -> None:
    """Then the body of call <index> is exactly <body>"""
    assert run.requests[index]["body"] == body


def _then_feed_holds_only(run: Run, *pending: str) -> None:
    """Then the pending expectations hold only the unanswered ones"""
    after = run.seen.get("after")
    assert isinstance(after, list), f"Expected the feed read again, got {after!r}"
    assert [e["inject_expectation_id"] for e in after] == list(pending)


def _then_update_is_refused_as_the_platform_would(run: Run) -> None:
    """Then the update is refused with the platform's 400 answer"""
    error = run.seen.get("error")
    assert error is not None, "Expected the update to be refused"
    assert getattr(error, "response_code", None) == 400


def _then_call_fails_needing_the_platform(run: Run, call: str) -> None:
    """Then the call fails with a NeedsPlatformError naming "<call>" """
    error = run.seen.get("error")
    assert isinstance(
        error, NeedsPlatformError
    ), f"Expected NeedsPlatformError: {error!r}"
    assert error.call == call


def _then_nothing_is_written(run: Run) -> None:
    """Then no call is written"""
    assert run.requests == []


def _then_collector_returns(run: Run) -> None:
    """Then the collector returns"""
    assert run.exit_code is None, f"Expected the collector to return: {run.exit_code}"


def _then_cycles_ran(run: Run, cycles: int) -> None:
    """Then the collector cycle ran <cycles> time(s)"""
    assert run.seen["cycles"] == cycles


def _then_exits_with(run: Run, code: int) -> None:
    """Then the collector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_refusal_says(run: Run, reason: str) -> None:
    """Then the refusal on stderr says "<reason>" """
    assert reason in run.stderr, f"Expected {reason!r} in {run.stderr!r}"


def _then_written_text_excludes(run: Run, secret: str) -> None:
    """Then "<secret>" appears nowhere in what is written"""
    assert run.written, "Expected something to be written"
    assert secret not in run.written


def _then_platform_mode_is_used(client_built: bool, heartbeat: MagicMock) -> None:
    """Then the platform client is built and the heartbeat starts"""
    assert client_built is True
    heartbeat.assert_called_once()


def test_dev_mode_never_reaches_the_platform(tmp_path: Path) -> None:
    """It runs without building the platform client or starting the heartbeat.

    Scenario: Dev mode never reaches the platform
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle reads "expectations_assets_for_source" from the platform client
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the platform client is never built
      And the heartbeat never starts
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_reading("expectations_assets_for_source")
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_platform_client_is_never_built(run)
    _then_heartbeat_never_starts(run)


def test_dev_mode_serves_the_pending_expectations_as_read(tmp_path: Path) -> None:
    """It serves the pending expectations exactly as the platform response holds them.

    Scenario: Dev mode serves the pending expectations as read
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle reads "expectations_assets_for_source" from the platform client
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then "expectations_assets_for_source" returns exactly those pending expectations
    """
    feed = _given_pending_expectations()
    path = _given_expectations_file(tmp_path, feed)
    cycle = _given_collector_reading("expectations_assets_for_source")
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_collector_reads(run, "expectations_assets_for_source", feed)


@pytest.mark.parametrize(
    ("read", "kind"),
    [
        ("detection_expectations_for_source", "DETECTION"),
        ("prevention_expectations_for_source", "PREVENTION"),
    ],
)
def test_dev_mode_serves_each_type_on_its_own_endpoint(
    tmp_path: Path, read: str, kind: str
) -> None:
    """It serves detection and prevention expectations on their own endpoints.

    Scenario Outline: Dev mode serves each type on its own endpoint
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle reads "<read>" from the platform client
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then "<read>" returns exactly the <kind> pending expectation

      Examples:
        | read                               | kind       |
        | detection_expectations_for_source  | DETECTION  |
        | prevention_expectations_for_source | PREVENTION |
    """
    feed = _given_pending_expectations()
    path = _given_expectations_file(tmp_path, feed)
    cycle = _given_collector_reading(read)
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_collector_reads(
        run, read, [e for e in feed if e["inject_expectation_type"] == kind]
    )


def test_dev_mode_lets_collectors_build_their_expectation_models(
    tmp_path: Path,
) -> None:
    """It lets collectors build their detection and prevention models from the feed.

    Scenario: Dev mode lets collectors build their expectation models
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle reads "models" from the platform client
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the expectation models are exactly a detection and a prevention, by id
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_reading("models")
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_models_are(
        run,
        (DetectionExpectation, DETECTION_ID),
        (PreventionExpectation, PREVENTION_ID),
    )


def test_dev_mode_writes_the_updates_the_platform_would_receive(
    tmp_path: Path,
) -> None:
    """It writes each expectation update, path and body, as the platform takes it.

    Scenario: Dev mode writes the updates the platform would receive
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle answers the detection as detected
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the calls written are exactly "PUT /api/injects/expectations/<detection>"
      And the body of call 0 is exactly the update the collector sent
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_answering((DETECTION_ID, True))
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_requests_are(run, ("PUT", f"/api/injects/expectations/{DETECTION_ID}"))
    _then_request_body_is(
        run,
        0,
        {
            "collector_id": COLLECTOR_ID,
            "result": "Detected",
            "is_success": True,
            "metadata": {"alertId": "a-42"},
        },
    )


def test_dev_mode_writes_bulk_updates_and_traces(tmp_path: Path) -> None:
    """It writes a bulk update and a bulk trace insert as the platform takes them.

    Scenario: Dev mode writes bulk updates and traces
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle answers both expectations at once, then traces the detection
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the calls written are exactly "PUT /api/injects/expectations/bulk" and "POST /api/inject-expectations-traces/bulk"
      And the body of call 0 is exactly {"inputs": <both updates>}
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_bulk_answering()
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_requests_are(
        run,
        ("PUT", "/api/injects/expectations/bulk"),
        ("POST", "/api/inject-expectations-traces/bulk"),
    )
    _then_request_body_is(
        run,
        0,
        {
            "inputs": {
                DETECTION_ID: {"collector_id": COLLECTOR_ID, "is_success": True},
                PREVENTION_ID: {"collector_id": COLLECTOR_ID, "is_success": False},
            }
        },
    )


def test_dev_mode_stops_serving_answered_expectations(tmp_path: Path) -> None:
    """It no longer serves an expectation once answered, as the platform does.

    Scenario: Dev mode stops serving answered expectations
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle answers the detection, then reads the feed again
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the pending expectations hold only the prevention
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_answering((DETECTION_ID, True))
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_feed_holds_only(run, PREVENTION_ID)


def test_dev_mode_runs_a_single_cycle_with_once(tmp_path: Path) -> None:
    """It runs the collector cycle once, then returns, with --once.

    Scenario: Dev mode runs a single cycle with --once
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle reads "expectations_assets_for_source" from the platform client
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the collector returns
      And the collector cycle ran 1 time(s)
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_reading("expectations_assets_for_source")
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_collector_returns(run)
    _then_cycles_ran(run, 1)


def test_dev_mode_reads_pending_expectations_piped_from_an_injector(
    tmp_path: Path,
) -> None:
    """It reads the pending expectations an injector emits, piped on stdin (chain).

    Scenario: Dev mode reads pending expectations piped from an injector
      Given the platform's pending expectations: one detection and one prevention
      And a SIEM collector configuration
      And a collector whose cycle reads "expectations_assets_for_source" from the platform client
      When the collector starts with "--dev --expectations - --once --out run.json", the expectations on stdin
      Then "expectations_assets_for_source" returns exactly those pending expectations
    """
    feed = _given_pending_expectations()
    cycle = _given_collector_reading("expectations_assets_for_source")
    run = _when_running_in_dev_mode(
        tmp_path, cycle, "--expectations", "-", stdin=json.dumps(feed)
    )
    _then_collector_reads(run, "expectations_assets_for_source", feed)


# ---- Constraints identified ----


def test_dev_mode_refuses_to_run_without_expectations(tmp_path: Path) -> None:
    """It exits with code 2 when no pending expectations are given.

    Scenario: Dev mode refuses to run without expectations
      Given a SIEM collector configuration
      And a collector whose cycle reads "expectations_assets_for_source" from the platform client
      When the collector starts with "--dev --once --out run.json"
      Then the collector cycle ran 0 time(s)
      And the refusal on stderr says "--expectations"
      And the collector exits with code 2
    """
    cycle = _given_collector_reading("expectations_assets_for_source")
    run = _when_running_in_dev_mode(tmp_path, cycle)
    _then_cycles_ran(run, 0)
    _then_refusal_says(run, "--expectations")
    _then_exits_with(run, 2)


@pytest.mark.parametrize(
    "feed",
    ["{not json", json.dumps({"inject_expectation_id": DETECTION_ID})],
    ids=["not JSON", "not a list"],
)
def test_dev_mode_refuses_what_is_not_a_pending_expectation_list(
    tmp_path: Path, feed: str
) -> None:
    """It exits with code 2 when the file is not the platform's pending expectations.

    Scenario Outline: Dev mode refuses what is not a pending expectation list
      Given <feed> saved to a file
      And a SIEM collector configuration
      And a collector whose cycle reads "expectations_assets_for_source" from the platform client
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the collector cycle ran 0 time(s)
      And the refusal on stderr says "not the platform's pending expectations"
      And the collector exits with code 2

      Examples:
        | feed       |
        | not JSON   |
        | not a list |
    """
    path = _given_expectations_file(tmp_path, feed)
    cycle = _given_collector_reading("expectations_assets_for_source")
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_cycles_ran(run, 0)
    _then_refusal_says(run, "not the platform's pending expectations")
    _then_exits_with(run, 2)


def test_dev_mode_refuses_an_update_the_platform_would_reject(
    tmp_path: Path,
) -> None:
    """It refuses an update the platform would reject, writing nothing for it.

    Scenario: Dev mode refuses an update the platform would reject
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle sends an update without its collector id
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the update is refused with the platform's 400 answer
      And no call is written
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_sending_an_invalid_update()
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_update_is_refused_as_the_platform_would(run)
    _then_nothing_is_written(run)


def test_dev_mode_fails_the_calls_that_need_the_platform(tmp_path: Path) -> None:
    """It fails a call the stand-in does not offer with an error naming it.

    Scenario: Dev mode fails the calls that need the platform
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose cycle upserts a payload on the platform
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then the call fails with a NeedsPlatformError naming "payload"
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_calling_the_platform()
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_call_fails_needing_the_platform(run, "payload")


def test_dev_mode_redacts_secrets_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It replaces secret environment values in everything it writes.

    Scenario: Dev mode redacts secrets from the environment
      Given the environment holds the secret SPLUNK_TOKEN "env-secret-42"
      And the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration
      And a collector whose update metadata contains that secret
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then "env-secret-42" appears nowhere in what is written
    """
    monkeypatch.setenv("SPLUNK_TOKEN", "env-secret-42")
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    cycle = _given_collector_leaking("env-secret-42")
    run = _when_running_in_dev_mode(tmp_path, cycle, "--expectations", path)
    _then_written_text_excludes(run, "env-secret-42")


def test_dev_mode_redacts_secrets_from_the_configuration(tmp_path: Path) -> None:
    """It replaces secret configuration values in everything it writes.

    Scenario: Dev mode redacts secrets from the configuration
      Given the platform's pending expectations: one detection and one prevention
      And those pending expectations saved to a file
      And a SIEM collector configuration, with splunk_password "cfg-secret-42"
      And a collector whose update metadata contains that secret
      When the collector starts with "--dev --expectations expectations.json --once --out run.json"
      Then "cfg-secret-42" appears nowhere in what is written
    """
    path = _given_expectations_file(tmp_path, _given_pending_expectations())
    configuration = _given_collector_configuration(
        tmp_path, splunk_password="cfg-secret-42"
    )
    cycle = _given_collector_leaking("cfg-secret-42")
    run = _when_running_in_dev_mode(
        tmp_path, cycle, "--expectations", path, configuration=configuration
    )
    _then_written_text_excludes(run, "cfg-secret-42")


def test_platform_mode_is_unchanged_without_dev(tmp_path: Path) -> None:
    """It builds the platform client and starts the heartbeat without --dev.

    Scenario: Platform mode is unchanged without --dev
      Given a SIEM collector configuration
      When the collector is built and set up without "--dev"
      Then the platform client is built and the heartbeat starts
    """
    client_built, heartbeat = _when_building_the_collector_without_dev(tmp_path)
    _then_platform_mode_is_used(client_built, heartbeat)
