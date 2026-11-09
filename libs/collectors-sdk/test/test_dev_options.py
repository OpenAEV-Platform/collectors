"""Tests for the dev options of a collector.

Feature: Collector dev options
  A collector reads the dev options common to every daemon plus its own: the pending
  expectations to answer and whether to run a single cycle. It never reads the options
  of an injector, and like every daemon it never acts on a flag that is not its own.
"""

from typing import Any, Callable

import collectors_sdk
import pytest

COLLECTOR_OPTIONS = ("--expectations", "--once")
COMMON_OPTIONS = ("--dev", "-h", "--out", "--record", "--replay")


def _given_collector_dev_options_reader() -> Callable[..., Any]:
    """Given the collectors SDK exposes the collector dev options"""
    reader = getattr(collectors_sdk, "collector_dev_options", None)
    assert reader is not None, "Expected collectors_sdk.collector_dev_options"
    return reader


def _given_collector_dev_help() -> Callable[[], str]:
    """Given the collectors SDK exposes the collector dev help"""
    helper = getattr(collectors_sdk, "collector_dev_help", None)
    assert helper is not None, "Expected collectors_sdk.collector_dev_help"
    return helper


def _given_command_line(*args: str) -> list[str]:
    """Given a collector command line with "<args>" """
    return list(args)


def _when_reading_dev_options(reader: Callable[..., Any], argv: list[str]) -> Any:
    """When the collector dev options are read"""
    return reader(argv)


def _when_reading_the_help(helper: Callable[[], str]) -> str:
    """When the collector dev help is read"""
    return helper()


def _then_options_are(options: Any, **expected: Any) -> None:
    """Then the options are <expected>"""
    actual = {name: getattr(options, name) for name in expected}
    assert actual == expected


def _then_options_have_no(options: Any, *names: str) -> None:
    """Then the options have no <names>"""
    present = [name for name in names if hasattr(options, name)]
    assert present == [], f"Expected no {present} on the collector options"


def _then_help_groups(text: str, heading: str, *options: str) -> None:
    """Then the help section "<heading>" lists exactly <options>"""
    section = text.split(f"{heading}:", 1)[1].split("\n\n", 1)[0]
    listed = tuple(
        token.rstrip(",")
        for line in section.splitlines()
        for token in line.split()
        if token.startswith("-") and line.lstrip().startswith(token)
    )
    assert listed == options, f"Expected {options} under {heading}, got {listed}"


def _then_help_has_no_section(text: str, heading: str) -> None:
    """Then the help has no "<heading>" section"""
    assert f"{heading}:" not in text


def test_collector_dev_mode_is_off_without_dev_flags() -> None:
    """It reports dev mode off, every collector option unset, without dev flags.

    Scenario: Collector dev mode is off without dev flags
      Given the collectors SDK exposes the collector dev options
      And a collector command line with ""
      When the collector dev options are read
      Then the options are disabled, with no expectations and no single cycle
    """
    reader = _given_collector_dev_options_reader()
    options = _when_reading_dev_options(reader, _given_command_line())
    _then_options_are(options, enabled=False, expectations=None, once=False)


def test_every_collector_dev_flag_is_exposed_with_the_common_ones() -> None:
    """It exposes the collector's own dev flags next to the common ones.

    Scenario: Every collector dev flag is exposed with the common ones
      Given the collectors SDK exposes the collector dev options
      And a collector command line with:
        | flag           | value           |
        | --dev          |                 |
        | --expectations | -               |
        | --once         |                 |
        | --out          | run.json        |
        | --record       | splunk.tape.json |
      When the collector dev options are read
      Then the options carry each value given
    """
    reader = _given_collector_dev_options_reader()
    argv = _given_command_line(
        "--dev",
        "--expectations",
        "-",
        "--once",
        "--out",
        "run.json",
        "--record",
        "splunk.tape.json",
    )
    options = _when_reading_dev_options(reader, argv)
    _then_options_are(
        options,
        enabled=True,
        expectations="-",
        once=True,
        out="run.json",
        record="splunk.tape.json",
        replay=None,
        help=False,
    )


def test_collector_never_reads_the_injector_options() -> None:
    """It holds no injector option, and leaves them alone on its command line.

    Scenario: A collector never reads the injector options
      Given the collectors SDK exposes the collector dev options
      And a collector command line with "--dev --inject inject.json --emit expectations"
      When the collector dev options are read
      Then the options have no inject and no emit
      And the options are enabled
    """
    reader = _given_collector_dev_options_reader()
    argv = _given_command_line(
        "--dev", "--inject", "inject.json", "--emit", "expectations"
    )
    options = _when_reading_dev_options(reader, argv)
    _then_options_have_no(options, "inject", "emit")
    _then_options_are(options, enabled=True)


@pytest.mark.parametrize(
    ("argv", "option", "unset"),
    [
        (["--dev", "--exp", "-"], "expectations", None),
        (["--dev", "--on"], "once", False),
    ],
    ids=["expectations", "once"],
)
def test_collector_options_are_read_only_under_their_full_name(
    argv: list[str], option: str, unset: Any
) -> None:
    """It reads a collector option only under its full name, never an abbreviation.

    Scenario Outline: Collector options are read only under their full name
      Given the collectors SDK exposes the collector dev options
      And a collector command line with "<argv>"
      When the collector dev options are read
      Then the options leave <option> unset
    """
    reader = _given_collector_dev_options_reader()
    options = _when_reading_dev_options(reader, argv)
    _then_options_are(options, **{option: unset})


def test_collector_dev_help_lists_the_common_and_collector_options() -> None:
    """It lists the common options and the collector's own, and no injector option.

    Scenario: The collector dev help lists the common and collector options
      Given the collectors SDK exposes the collector dev help
      When the collector dev help is read
      Then the help section "common options" lists exactly --dev, -h, --out, --record and --replay
      And the help section "collector options" lists exactly --expectations and --once
      And the help has no "injector options" section
    """
    helper = _given_collector_dev_help()
    text = _when_reading_the_help(helper)
    _then_help_groups(text, "common options", *COMMON_OPTIONS)
    _then_help_groups(text, "collector options", *COLLECTOR_OPTIONS)
    _then_help_has_no_section(text, "injector options")
