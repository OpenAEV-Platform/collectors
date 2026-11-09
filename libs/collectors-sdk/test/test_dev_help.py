"""Tests for the dev help of a collector.

Feature: Dev help of a collector
  Started with "--dev --help", a collector prints the dev options and what each one is
  for, then exits with code 0, before reaching the platform or running anything.
"""

import io
import sys
from typing import Any, NamedTuple
from unittest.mock import MagicMock, patch

import pytest
from collectors_sdk import CollectorDaemon
from xtm_oaev_sdk import Configuration


class Run(NamedTuple):
    exit_code: Any
    stdout: str
    client_built: bool


class _RecordingCollector(CollectorDaemon):
    client_built = False

    def _create_default_api_client(self):
        _RecordingCollector.client_built = True
        return MagicMock()


def _given_collector_configuration() -> Configuration:
    """Given a collector configuration"""
    return Configuration(
        config_hints={
            "collector_id": {"data": "c0ffee-collector"},
            "collector_name": {"data": "Lab SIEM"},
            "collector_log_level": {"data": "info"},
        }
    )


def _when_starting(configuration: Configuration, *args: str) -> Run:
    """When the collector starts with "<args>" """
    stdout = io.StringIO()
    _RecordingCollector.client_built = False
    with (
        patch.object(sys, "argv", ["openaev-lab-siem", *args]),
        patch.object(sys, "stdout", stdout),
        patch("xtm_oaev_sdk.PingAlive.start"),
    ):
        try:
            _RecordingCollector(
                configuration=configuration,
                callback=MagicMock(),
                logger=MagicMock(),
                collector_type="openaev_lab_siem",
            )
            exit_code: Any = "the collector went on"
        except SystemExit as exit_:
            exit_code = exit_.code
    return Run(exit_code, stdout.getvalue(), _RecordingCollector.client_built)


def _then_dev_help_is_printed(run: Run) -> None:
    """Then the common and collector dev options are printed, each with what it is for"""
    for option in ("--expectations", "--out", "--once", "--record", "--replay"):
        assert option in run.stdout, f"Expected {option} in {run.stdout!r}"
    assert "--inject" not in run.stdout, "Expected no injector option"


def _then_collector_goes_on(run: Run) -> None:
    """Then the collector goes on, printing no dev help"""
    assert run.exit_code == "the collector went on", f"Exited with {run.exit_code}"
    assert "common options" not in run.stdout


def _then_exits_with(run: Run, code: int) -> None:
    """Then the collector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_platform_client_is_never_built(run: Run) -> None:
    """Then the platform client is never built"""
    assert run.client_built is False


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_dev_help_prints_the_dev_options_and_exits(flag: str) -> None:
    """It prints the dev options and exits with code 0, before reaching the platform.

    Scenario Outline: The dev help prints the dev options and exits
      Given a collector configuration
      When the collector starts with "--dev <flag>"
      Then the common and collector dev options are printed, each with what it is for
      And the collector exits with code 0
      And the platform client is never built

      Examples:
        | flag   |
        | --help |
        | -h     |
    """
    configuration = _given_collector_configuration()
    run = _when_starting(configuration, "--dev", flag)
    _then_dev_help_is_printed(run)
    _then_exits_with(run, 0)
    _then_platform_client_is_never_built(run)


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_without_dev_stays_the_collector_s_own(flag: str) -> None:
    """It leaves -h and --help to the collector when --dev is absent.

    Scenario Outline: Help without --dev stays the collector's own
      Given a collector configuration
      When the collector starts with "<flag>"
      Then the collector goes on, printing no dev help

      Examples:
        | flag   |
        | --help |
        | -h     |
    """
    configuration = _given_collector_configuration()
    run = _when_starting(configuration, flag)
    _then_collector_goes_on(run)
