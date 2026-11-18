"""Tests for recording and replaying a collector's outside calls in dev mode.

Feature: Record a collector's outside calls, replay them offline
  With --record PATH, a dev run writes every outside call the collector makes (its
  security product's API) and the answers to a tape. With --replay PATH, the same run
  answers those calls from the tape: offline, with no product, it writes the same
  expectation updates.
"""

import http.server
import io
import json
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any, Callable, NamedTuple
from unittest.mock import MagicMock, patch

import pytest
from collectors_sdk import CollectorDaemon
from xtm_oaev_sdk import Configuration

COLLECTOR_ID = "c0ffee00-0000-4000-8000-000000000001"
DETECTION_ID = "4e5d0000-0000-4000-8000-00000000000d"
PRODUCT_TOKEN = "siem-token-12345"


class Run(NamedTuple):
    exit_code: Any
    requests: list[dict[str, Any]]
    stderr: str


class _SiemApi(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps({"alerts": [{"id": "a-42", "ip": "10.0.0.5"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SiemApi:
    """The collector's security product API, running locally, which a test can shut
    down."""

    def __init__(self) -> None:
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SiemApi)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self.running = True

    def shut_down(self) -> None:
        if self.running:
            self._server.shutdown()
            self._server.server_close()
            self.running = False


@pytest.fixture
def siem_api() -> Any:
    api = SiemApi()
    yield api
    api.shut_down()


def _given_pending_detection(tmp_path: Path) -> str:
    """Given the platform's pending expectations: one detection, saved to a file"""
    path = tmp_path / "expectations.json"
    path.write_text(
        json.dumps(
            [
                {
                    "inject_expectation_id": DETECTION_ID,
                    "inject_expectation_type": "DETECTION",
                    "inject_expectation_signatures": [
                        {"type": "target_ipv4_address", "value": "10.0.0.5"}
                    ],
                }
            ]
        )
    )
    return str(path)


def _given_collector_configuration(tmp_path: Path) -> Configuration:
    """Given a SIEM collector configuration, with its product token"""
    icon = tmp_path / "icon.png"
    icon.write_bytes(b"\x89PNG")
    return Configuration(
        config_hints={
            "collector_id": {"data": COLLECTOR_ID},
            "collector_name": {"data": "Lab SIEM"},
            "collector_icon_filepath": {"data": str(icon)},
            "collector_period": {"data": 60},
            "collector_log_level": {"data": "info"},
            "siem_token": {"data": PRODUCT_TOKEN},
        }
    )


def _given_searching_collector(api_url: str) -> Callable[..., None]:
    """Given a collector whose cycle searches its SIEM for each pending detection and
    answers it"""

    def cycle(collector: Any) -> None:
        manager = collector.api.inject_expectation
        for expectation in manager.expectations_assets_for_source(
            source_id=COLLECTOR_ID
        ):
            request = urllib.request.Request(
                f"{api_url}/alerts?ip=10.0.0.5",
                headers={"Authorization": f"Bearer {PRODUCT_TOKEN}"},
            )
            with urllib.request.urlopen(request) as answer:
                alerts = json.loads(answer.read())["alerts"]
            manager.update(
                expectation["inject_expectation_id"],
                inject_expectation={
                    "collector_id": COLLECTOR_ID,
                    "is_success": bool(alerts),
                    "metadata": {"alertId": alerts[0]["id"] if alerts else ""},
                },
            )

    return cycle


def _given_the_api_shut_down(api: SiemApi) -> None:
    """Given the SIEM API is shut down: nothing answers on its URL any more"""
    api.shut_down()


def _when_running(tmp_path: Path, cycle: Callable[..., None], *args: str) -> Run:
    """When the collector starts with "--dev <args> --once --out run.json" """
    out = tmp_path / "run.json"
    out.unlink(missing_ok=True)
    argv = ["openaev-lab-siem", "--dev", *args, "--once", "--out", str(out)]
    stderr = io.StringIO()
    configuration = _given_collector_configuration(tmp_path)
    holder: dict[str, Any] = {"exit_code": "never returned"}
    with (
        patch.object(sys, "argv", argv),
        patch.object(sys, "stderr", stderr),
        patch("xtm_oaev_sdk.PingAlive.start"),
    ):

        def start() -> None:
            try:
                holder["collector"] = CollectorDaemon(
                    configuration=configuration,
                    callback=lambda: cycle(holder["collector"]),
                    logger=MagicMock(),
                    collector_type="openaev_lab_siem",
                )
                holder["collector"].start()
                holder["exit_code"] = None
            except SystemExit as exit_:
                holder["exit_code"] = exit_.code

        runner = threading.Thread(target=start, daemon=True)
        runner.start()
        runner.join(timeout=10)
    written = out.read_text() if out.exists() else ""
    requests = json.loads(written) if written else []
    return Run(holder["exit_code"], requests, stderr.getvalue())


def _then_answers_detected(run: Run) -> None:
    """Then the collector answers the detection as detected, with alert a-42"""
    assert [(r["method"], r["path"], r["body"]) for r in run.requests] == [
        (
            "PUT",
            f"/api/injects/expectations/{DETECTION_ID}",
            {
                "collector_id": COLLECTOR_ID,
                "is_success": True,
                "metadata": {"alertId": "a-42"},
            },
        )
    ], run.requests


def _then_tape_holds_the_search(path: Path) -> None:
    """Then the tape holds the SIEM search"""
    assert path.exists(), f"Expected a tape at {path}"
    calls = json.loads(path.read_text())["calls"]
    assert [c["kind"] for c in calls] == ["http"], calls
    assert "/alerts?ip=10.0.0.5" in calls[0]["request"]["url"]


def _then_tape_names_the_daemon(path: Path) -> None:
    """Then the tape's header names the collector "Lab SIEM" """
    assert json.loads(path.read_text())["daemon"] == "Lab SIEM"


def _then_tape_excludes(path: Path, secret: str) -> None:
    """Then "<secret>" appears nowhere on the tape"""
    assert secret not in path.read_text()


def _then_returns(run: Run) -> None:
    """Then the collector returns"""
    assert run.exit_code is None, f"Expected the collector to return: {run.exit_code}"


def _then_exits_with(run: Run, code: int) -> None:
    """Then the collector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_refusal_says(run: Run, reason: str) -> None:
    """Then the refusal on stderr says "<reason>" """
    assert reason in run.stderr, f"Expected {reason!r} in {run.stderr!r}"


def test_recording_writes_the_collector_s_outside_calls(
    tmp_path: Path, siem_api: SiemApi
) -> None:
    """It runs the cycle for real and writes its SIEM search to the tape.

    Scenario: Recording writes the collector's outside calls
      Given the platform's pending expectations: one detection, saved to a file
      And a SIEM collector configuration, with its product token
      And a collector whose cycle searches its SIEM for each pending detection and answers it
      When the collector starts with "--dev --expectations expectations.json --record tape.json --once --out run.json"
      Then the collector answers the detection as detected, with alert a-42
      And the tape holds the SIEM search
      And "siem-token-12345" appears nowhere on the tape
      And the collector returns
    """
    tape = tmp_path / "tape.json"
    expectations = _given_pending_detection(tmp_path)
    cycle = _given_searching_collector(siem_api.url)
    run = _when_running(
        tmp_path, cycle, "--expectations", expectations, "--record", str(tape)
    )
    _then_answers_detected(run)
    _then_tape_holds_the_search(tape)
    _then_tape_names_the_daemon(tape)
    _then_tape_excludes(tape, PRODUCT_TOKEN)
    _then_returns(run)


def test_replaying_runs_the_cycle_offline(tmp_path: Path, siem_api: SiemApi) -> None:
    """It runs the same cycle from the tape, with the SIEM shut down.

    Scenario: Replaying runs the cycle offline
      Given the platform's pending expectations: one detection, saved to a file
      And a SIEM collector configuration, with its product token
      And a collector whose cycle searches its SIEM for each pending detection and answers it
      And the collector ran with "--record tape.json"
      And the SIEM API is shut down: nothing answers on its URL any more
      When the collector starts with "--dev --expectations expectations.json --replay tape.json --once --out run.json"
      Then the collector answers the detection as detected, with alert a-42
      And the collector returns
    """
    tape = tmp_path / "tape.json"
    expectations = _given_pending_detection(tmp_path)
    cycle = _given_searching_collector(siem_api.url)
    _when_running(
        tmp_path, cycle, "--expectations", expectations, "--record", str(tape)
    )
    _given_the_api_shut_down(siem_api)
    run = _when_running(
        tmp_path, cycle, "--expectations", expectations, "--replay", str(tape)
    )
    _then_answers_detected(run)
    _then_returns(run)


# ---- Constraints identified ----


def test_record_and_replay_together_are_refused(
    tmp_path: Path, siem_api: SiemApi
) -> None:
    """It exits with code 2 when asked to record and replay at once.

    Scenario: Record and replay together are refused
      Given the platform's pending expectations: one detection, saved to a file
      And a SIEM collector configuration, with its product token
      When the collector starts with "--dev --expectations expectations.json --record a.tape.json --replay b.tape.json --once --out run.json"
      Then the refusal on stderr says "--record" and "--replay"
      And the collector exits with code 2
    """
    expectations = _given_pending_detection(tmp_path)
    cycle = _given_searching_collector(siem_api.url)
    run = _when_running(
        tmp_path,
        cycle,
        "--expectations",
        expectations,
        "--record",
        str(tmp_path / "a.tape.json"),
        "--replay",
        str(tmp_path / "b.tape.json"),
    )
    _then_refusal_says(run, "--record")
    _then_refusal_says(run, "--replay")
    _then_exits_with(run, 2)


def test_a_tape_that_cannot_be_replayed_is_refused(
    tmp_path: Path, siem_api: SiemApi
) -> None:
    """It exits with code 2, before any cycle, when the replay tape cannot be read.

    Scenario: A tape that cannot be replayed is refused
      Given the platform's pending expectations: one detection, saved to a file
      And a tape file that is not JSON
      When the collector starts with "--dev --expectations expectations.json --replay tape.json --once --out run.json"
      Then the refusal on stderr says "not a JSON tape"
      And the collector exits with code 2
    """
    tape = tmp_path / "tape.json"
    tape.write_text("calls: []")
    expectations = _given_pending_detection(tmp_path)
    cycle = _given_searching_collector(siem_api.url)
    run = _when_running(
        tmp_path, cycle, "--expectations", expectations, "--replay", str(tape)
    )
    _then_refusal_says(run, "not a JSON tape")
    _then_exits_with(run, 2)
