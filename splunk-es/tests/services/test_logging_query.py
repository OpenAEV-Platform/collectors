"""Tests for the Splunk ES Logging query builder."""

import pytest
from src.models.configs.splunkes_configs import LOGGING_TEMPLATE_PLACEHOLDERS
from src.services.client_api import DEFAULT_QUERY_TEMPLATE
from src.services.logging_query import (
    LoggingQuery,
    Unqueryable,
    build_logging_query,
)

INJECT_ID = "877b423b-ae91-4fc5-86c3-fa8ea3c938ba"
AGENT_ID = "1402422f-2eaa-4fbd-80b2-b30df1b83b19"
MARKER = f"oaev-implant-{INJECT_ID}-agent-{AGENT_ID}"
MARKER_URL = f"/api/injects/{INJECT_ID}/{AGENT_ID}/executable-payload"
START = "2026-11-03T14:00:00.123456789Z"
END = "2026-11-03T14:10:00Z"
START_EPOCH = 1793714400
END_EPOCH = 1793715000


def _signatures(**values: str | list[str]) -> list[dict[str, str]]:
    """Build expectation signatures, with the window by default."""
    values.setdefault("start_date", START)
    values.setdefault("end_date", END)
    signatures = []
    for kind, value in values.items():
        for item in value if isinstance(value, list) else [value]:
            signatures.append({"type": kind, "value": item})
    return signatures


def test_marker_and_ips_build_one_or_group():
    """The marker, its callback URL and every IP are ORed in one group."""
    # Arrange
    signatures = _signatures(
        parent_process_name=MARKER,
        source_ipv4_address="192.168.56.10",
        target_ipv4_address="192.168.56.1",
    )

    # Act
    query = build_logging_query(signatures, "sysmon")

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.spl == (  # noqa: S101
        f"search index IN (sysmon) earliest={START_EPOCH} latest={END_EPOCH + 1} "
        f'("{MARKER}" OR "{MARKER_URL}" OR "192.168.56.10" OR "192.168.56.1")'
        " | table _time, index, host, sourcetype, _raw"
    )
    assert query.marker_values == [MARKER, MARKER_URL]  # noqa: S101
    assert query.source_ips == ["192.168.56.10"]  # noqa: S101
    assert query.target_ips == ["192.168.56.1"]  # noqa: S101


def test_window_is_epoch_and_inclusive():
    """The window is in epoch seconds, the end shifted by one in the SPL only."""
    # Act
    query = build_logging_query(_signatures(source_ipv4_address="10.0.0.1"), "sysmon")

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.earliest == START_EPOCH  # noqa: S101
    assert query.latest == END_EPOCH  # noqa: S101
    assert f"earliest={START_EPOCH} latest={END_EPOCH + 1} " in query.spl  # noqa: S101


def test_several_indexes_are_listed():
    """Every configured index is searched."""
    # Act
    query = build_logging_query(
        _signatures(source_ipv4_address="10.0.0.1"),
        "sysmon,wineventlog,net*",
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.spl.startswith(  # noqa: S101
        "search index IN (sysmon,wineventlog,net*) "
    )


def test_ipv4_and_ipv6_are_both_searched():
    """IPv4 and IPv6 signatures go to the source and target lists."""
    # Act
    query = build_logging_query(
        _signatures(
            source_ipv4_address="10.0.0.1",
            source_ipv6_address="2001:db8::1",
            target_ipv4_address="10.0.0.2",
            target_ipv6_address="2001:db8::2",
        ),
        "sysmon",
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.source_ips == ["10.0.0.1", "2001:db8::1"]  # noqa: S101
    assert query.target_ips == ["10.0.0.2", "2001:db8::2"]  # noqa: S101
    assert (  # noqa: S101
        '("10.0.0.1" OR "2001:db8::1" OR "10.0.0.2" OR "2001:db8::2")' in query.spl
    )


def test_quotes_and_backslashes_are_escaped():
    """A value cannot close its SPL string: backslashes and quotes are escaped."""
    # Arrange
    marker = 'evil" | delete \\'

    # Act
    query = build_logging_query(_signatures(parent_process_name=marker), "sysmon")

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert '("evil\\" | delete \\\\")' in query.spl  # noqa: S101
    # The original value is kept for the matcher.
    assert query.marker_values == ['evil" | delete \\']  # noqa: S101


def test_marker_without_uuids_has_no_url_alternate():
    """A marker that is not an implant name is searched alone."""
    # Act
    query = build_logging_query(_signatures(parent_process_name="custom.exe"), "sysmon")

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.marker_values == ["custom.exe"]  # noqa: S101


def test_duplicate_and_blank_values_are_dropped():
    """Repeated or blank signature values are searched once."""
    # Act
    query = build_logging_query(
        _signatures(
            source_ipv4_address=["10.0.0.1", "10.0.0.1", "  "],
            target_ipv4_address="10.0.0.1",
        ),
        "sysmon",
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.source_ips == ["10.0.0.1"]  # noqa: S101
    assert query.target_ips == ["10.0.0.1"]  # noqa: S101
    assert '("10.0.0.1")' in query.spl  # noqa: S101


def test_hostname_is_not_a_signal():
    """The target hostname is never searched."""
    # Act
    query = build_logging_query(
        _signatures(
            source_ipv4_address="10.0.0.1", target_hostname_address="WIN-LAB01"
        ),
        "sysmon",
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert "WIN-LAB01" not in query.spl  # noqa: S101


def test_fractional_window_end_is_rounded_up():
    """A fraction of a second at the end widens the window, never cuts it."""
    # Act
    query = build_logging_query(
        _signatures(end_date="2026-11-03T14:10:00.5Z", source_ipv4_address="1.1.1.1"),
        "sysmon",
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.earliest == START_EPOCH  # noqa: S101
    assert query.latest == END_EPOCH + 1  # noqa: S101
    assert f"latest={END_EPOCH + 2} " in query.spl  # noqa: S101


def test_zero_fraction_is_not_rounded_up():
    """An end at an exact second stays as it is."""
    # Act
    query = build_logging_query(
        _signatures(end_date="2026-11-03T14:10:00.000Z", source_ipv4_address="1.1.1.1"),
        "sysmon",
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.latest == END_EPOCH  # noqa: S101


@pytest.mark.parametrize(
    "signatures, reason",
    [
        (
            [
                {"type": "start_date", "value": START},
                {"type": "source_ipv4_address", "value": "10.0.0.1"},
            ],
            "no end_date",
        ),
        (
            [
                {"type": "end_date", "value": END},
                {"type": "source_ipv4_address", "value": "10.0.0.1"},
            ],
            "no start_date",
        ),
        (
            _signatures(end_date="not a date", source_ipv4_address="10.0.0.1"),
            "start_date or end_date is not a valid date",
        ),
        (
            _signatures(start_date=END, end_date=START, source_ipv4_address="1.1.1.1"),
            "start_date is after end_date",
        ),
        (_signatures(), "no marker and no IP"),
        (
            _signatures(
                parent_process_name=" ",
                source_ipv4_address="",
                target_hostname_address="WIN-LAB01",
            ),
            "no marker and no IP",
        ),
    ],
    ids=[
        "no-end-date",
        "no-start-date",
        "bad-date",
        "reversed-window",
        "no-signal",
        "blank-signals",
    ],
)
def test_unqueryable_expectations(signatures, reason):
    """No search is built without a window or without any signal."""
    # Act
    query = build_logging_query(signatures, "sysmon")

    # Assert
    assert query == Unqueryable(reason)  # noqa: S101


def test_no_index_is_unqueryable():
    """Without an index there is nothing to search."""
    # Act
    query = build_logging_query(_signatures(source_ipv4_address="10.0.0.1"), None)

    # Assert
    assert query == Unqueryable("no Logging index configured")  # noqa: S101


def test_detection_template_is_unchanged():
    """The Logging search does not touch the Detection query template."""
    # Assert
    assert DEFAULT_QUERY_TEMPLATE.startswith("index={alerts_index} ")  # noqa: S101
    assert "earliest={start_date} latest={end_date}" in (  # noqa: S101
        DEFAULT_QUERY_TEMPLATE
    )


def test_custom_template_receives_every_value():
    """A custom template gets the window and the signals."""
    # Arrange
    template = (
        "search index IN ({indexes}) earliest={earliest} latest={latest} "
        "(src_ip IN ({source_ips}) OR dest_ip IN ({target_ips})) "
        "| table _time, index, _raw"
    )
    signatures = _signatures(
        parent_process_name=MARKER,
        source_ipv4_address="192.168.56.10",
        target_ipv4_address="192.168.56.1",
    )

    # Act
    query = build_logging_query(signatures, "sysmon,net*", template)

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.spl == (  # noqa: S101
        f"search index IN (sysmon,net*) earliest={START_EPOCH} "
        f"latest={END_EPOCH + 1} "
        '(src_ip IN ("192.168.56.10") OR dest_ip IN ("192.168.56.1")) '
        "| table _time, index, _raw"
    )
    # The window and signals the matcher uses do not depend on the template.
    assert query.earliest == START_EPOCH  # noqa: S101
    assert query.marker_values == [MARKER, MARKER_URL]  # noqa: S101


def test_custom_template_empty_list_matches_nothing():
    """An empty signal list is written as "", never as a wildcard."""
    # Act
    query = build_logging_query(
        _signatures(source_ipv4_address="10.0.0.1"),
        "sysmon",
        "earliest={earliest} latest={latest} dest_ip IN ({target_ips}) "
        "| table _time, index, _raw",
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert 'dest_ip IN ("")' in query.spl  # noqa: S101


@pytest.mark.parametrize(
    "template, expected_start",
    [
        ("index=sysmon earliest={earliest} latest={latest}", "search index=sysmon "),
        ("search index=sysmon earliest={earliest} latest={latest}", "search index="),
        ("| tstats count where earliest={earliest} latest={latest}", "| tstats "),
    ],
    ids=["no-command", "search", "generating-command"],
)
def test_custom_template_starts_with_a_command(template, expected_start):
    """A template without a leading command gets "search" in front of it."""
    # Act
    query = build_logging_query(
        _signatures(source_ipv4_address="10.0.0.1"), "sysmon", template
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.spl.startswith(expected_start)  # noqa: S101


def test_builder_fills_exactly_the_allowed_placeholders():
    """The config allows exactly the placeholders the builder fills."""
    # Arrange
    template = " ".join(f"{{{name}}}" for name in sorted(LOGGING_TEMPLATE_PLACEHOLDERS))

    # Act: an unfilled placeholder would raise KeyError here.
    query = build_logging_query(
        _signatures(parent_process_name=MARKER), "sysmon", template
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert "{" not in query.spl.replace("{{", "")  # noqa: S101
