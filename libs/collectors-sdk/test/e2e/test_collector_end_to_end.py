"""End-to-end tests of a collector run as a process, without the platform.

Feature: A collector runs end to end without the platform
  A lab collector, started as its own process with --dev, reads the pending expectations
  an injector emits, piped on its stdin, answers them in one cycle, and writes the
  updates and traces the platform would have received.
"""

import json
import subprocess
import sys
from pathlib import Path

LAB_COLLECTOR = Path(__file__).parent / "lab_collector.py"
PENDING = [
    {
        "inject_expectation_id": "5ea73628-3069-5293-a7ff-790e4fad3c30",
        "inject_expectation_type": "DETECTION",
        "inject_expectation_name": "Ping detected",
        "inject_expectation_expected_score": 100.0,
        "inject_expiration_time": 21600,
        "inject_expectation_group": False,
        "inject_expectation_status": "PENDING",
        "inject_expectation_created_at": "2026-11-10T08:00:00Z",
        "inject_expectation_updated_at": "2026-11-10T08:00:00Z",
        "inject_expectation_signatures": [
            {"type": "target_ipv4_address", "value": "10.0.0.7"}
        ],
        "inject_expectation_results": [],
        "inject_expectation_traces": [],
        "inject_expectation_inject": "e746cab3-888c-43d9-9f94-f0cac9ab30bf",
        "inject_expectation_asset": "asset-lab-1",
        "target_id": "asset-lab-1",
    }
]


def _when_starting(cwd: Path, stdin: str, *args: str) -> subprocess.CompletedProcess:
    """When the lab collector starts as a process with "--dev <args>" and <stdin>"""
    return subprocess.run(
        [sys.executable, str(LAB_COLLECTOR), "--dev", *args],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_a_collector_process_answers_the_expectations_piped_to_it(
    tmp_path: Path,
) -> None:
    """It answers the pending expectations piped on stdin, writing the platform's calls.

    Scenario: A collector process answers the expectations piped to it
      Given one pending detection signed with 10.0.0.7, as an injector emits it
      When the lab collector starts as a process with "--dev --expectations - --once --out run.json", the expectation on stdin
      Then it exits with code 0
      And run.json holds the update, detected, then the trace of that expectation
    """
    run = _when_starting(
        tmp_path,
        json.dumps(PENDING),
        "--expectations",
        "-",
        "--once",
        "--out",
        "run.json",
    )
    assert run.returncode == 0, run.stderr
    calls = json.loads((tmp_path / "run.json").read_text())
    assert [(c["method"], c["path"]) for c in calls] == [
        ("PUT", f"/api/injects/expectations/{PENDING[0]['inject_expectation_id']}"),
        ("POST", "/api/inject-expectations-traces/bulk"),
    ]
    assert calls[0]["body"]["is_success"] is True


def test_a_collector_process_refuses_what_is_not_pending_expectations(
    tmp_path: Path,
) -> None:
    """It exits with code 2, running no cycle, when stdin is not pending expectations.

    Scenario: A collector process refuses what is not pending expectations
      When the lab collector starts as a process with "--dev --expectations - --once", a JSON object on stdin
      Then it exits with code 2
      And stderr says "not the platform's pending expectations"
    """
    run = _when_starting(
        tmp_path, json.dumps({"x": 1}), "--expectations", "-", "--once"
    )
    assert run.returncode == 2
    assert "not the platform's pending expectations" in run.stderr
