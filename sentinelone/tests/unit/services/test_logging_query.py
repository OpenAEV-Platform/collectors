"""Tests for the Logging search filter builder."""

from datetime import datetime, timezone

import pytest
from src.services.logging_query import LoggingQuery, Unqueryable, build_logging_query
from src.services.utils.s1ql import dv_string, s1ql_string

MARKER = "oaev-implant-11111111-2222-3333-4444-555555555555-agent-66666666-7777-8888-9999-000000000000"
BASE = "dataSource.name='SentinelOne' dataSource.category='security'"


def _signatures(**values):  # type: ignore
    """Build signatures as {"type", "value"} mappings, with a valid window."""
    values.setdefault("start_date", "2026-11-24T08:00:00Z")
    values.setdefault("end_date", "2026-11-24T09:00:00Z")
    signatures = []
    for kind, value in values.items():
        for item in value if isinstance(value, list) else [value]:
            signatures.append({"type": kind, "value": item})
    return signatures


def test_sdl_filter_with_marker_and_ips():
    """SaaS: the marker in the three process fields OR the IPs in both IP fields."""
    # Arrange
    signatures = _signatures(
        parent_process_name=MARKER,
        source_ipv4_address="10.0.0.1",
        target_ipv6_address="fe80::1",
    )

    # Act
    query = build_logging_query(signatures, self_hosted=False)

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.filter == (  # noqa: S101
        f"{BASE} ("
        f"tgt.process.name contains:anycase '{MARKER}'"
        f" or src.process.name contains:anycase '{MARKER}'"
        f" or src.process.parent.name contains:anycase '{MARKER}'"
        " or src.ip.address in ('10.0.0.1','fe80::1')"
        " or dst.ip.address in ('10.0.0.1','fe80::1'))"
    )
    assert query.markers == [MARKER]  # noqa: S101
    assert query.source_ips == ["10.0.0.1"]  # noqa: S101
    assert query.target_ips == ["fe80::1"]  # noqa: S101


def test_sdl_filter_with_marker_only_has_no_ip_condition():
    """No IP signature: the filter has no empty "in ()" condition."""
    # Act
    query = build_logging_query(
        _signatures(parent_process_name=MARKER), self_hosted=False
    )

    # Assert
    assert "ip.address" not in query.filter  # noqa: S101


def test_sdl_filter_with_ips_only_has_no_marker_condition():
    """No marker signature: the filter searches the IPs only."""
    # Act
    query = build_logging_query(
        _signatures(source_ipv4_address="10.0.0.1"), self_hosted=False
    )

    # Assert
    assert query.filter == (  # noqa: S101
        f"{BASE} (src.ip.address in ('10.0.0.1')" " or dst.ip.address in ('10.0.0.1'))"
    )


def test_dv_filter_with_marker_and_ips():
    """Self-hosted: the same search in S1QL 1.0, without the SDL scope."""
    # Arrange
    signatures = _signatures(parent_process_name=MARKER, target_ipv4_address="10.0.0.2")

    # Act
    query = build_logging_query(signatures, self_hosted=True)

    # Assert
    assert query.filter == (  # noqa: S101
        f'TgtProcName ContainsCIS "{MARKER}"'
        f' OR SrcProcName ContainsCIS "{MARKER}"'
        f' OR SrcProcParentName ContainsCIS "{MARKER}"'
        ' OR SrcIP In ("10.0.0.2")'
        ' OR DstIP In ("10.0.0.2")'
    )


def test_ip_in_both_source_and_target_is_searched_once():
    """An IP given as source and target appears once in each IP condition."""
    # Act
    query = build_logging_query(
        _signatures(source_ipv4_address="10.0.0.1", target_ipv4_address="10.0.0.1"),
        self_hosted=False,
    )

    # Assert
    assert "in ('10.0.0.1')" in query.filter  # noqa: S101
    assert query.source_ips == ["10.0.0.1"]  # noqa: S101
    assert query.target_ips == ["10.0.0.1"]  # noqa: S101


def test_blank_signature_values_are_ignored():
    """Blank values are dropped, so blank IPs alone are no signal."""
    # Act
    query = build_logging_query(
        _signatures(source_ipv4_address=["", "  "], parent_process_name=" "),
        self_hosted=False,
    )

    # Assert
    assert query == Unqueryable("no marker and no IP")  # noqa: S101


@pytest.mark.parametrize("self_hosted", [False, True], ids=["sdl", "dv"])
def test_quote_in_a_value_cannot_add_conditions(self_hosted):
    """A quote in a value stays inside its string: no condition is added."""
    # Arrange
    value = "x' or tgt.process.name contains 'a\" OR SrcIP In (\"1"

    # Act
    query = build_logging_query(
        _signatures(parent_process_name=value), self_hosted=self_hosted
    )

    # Assert
    quoted = dv_string(value) if self_hosted else s1ql_string(value)
    assert quoted in query.filter  # noqa: S101
    assert query.filter.count(quoted) == 3  # noqa: S101


def test_s1ql_strings_escape_backslashes_before_quotes():
    """Backslashes are escaped first, so an escaped quote stays escaped."""
    # Act / Assert
    assert s1ql_string("a'b\\c") == "'a\\'b\\\\c'"  # noqa: S101
    assert dv_string('a"b\\c') == '"a\\"b\\\\c"'  # noqa: S101


def test_window_is_rounded_outwards_to_the_second():
    """The start is rounded down and the end up, nanoseconds included."""
    # Act
    query = build_logging_query(
        _signatures(
            parent_process_name=MARKER,
            start_date="2026-11-24T08:00:00.987654321Z",
            end_date="2026-11-24T09:00:00.000000001Z",
        ),
        self_hosted=False,
    )

    # Assert
    assert query.start == datetime(
        2026, 11, 24, 8, 0, 0, tzinfo=timezone.utc
    )  # noqa: S101
    assert query.end == datetime(
        2026, 11, 24, 9, 0, 1, tzinfo=timezone.utc
    )  # noqa: S101


def test_window_with_offset_or_no_time_zone_is_read_as_utc():
    """An offset is converted to UTC; a date without time zone is UTC."""
    # Act
    query = build_logging_query(
        _signatures(
            parent_process_name=MARKER,
            start_date="2026-11-24T10:00:00+02:00",
            end_date="2026-11-24T09:00:00",
        ),
        self_hosted=False,
    )

    # Assert
    assert query.start == datetime(
        2026, 11, 24, 8, 0, 0, tzinfo=timezone.utc
    )  # noqa: S101
    assert query.end == datetime(
        2026, 11, 24, 9, 0, 0, tzinfo=timezone.utc
    )  # noqa: S101


def test_window_with_equal_start_and_end_is_kept():
    """A start equal to the end is a valid window, rounded outwards."""
    # Act
    query = build_logging_query(
        _signatures(
            parent_process_name=MARKER,
            start_date="2026-11-24T08:00:00.500Z",
            end_date="2026-11-24T08:00:00.500Z",
        ),
        self_hosted=False,
    )

    # Assert
    assert isinstance(query, LoggingQuery)  # noqa: S101
    assert query.start == datetime(  # noqa: S101
        2026, 11, 24, 8, 0, 0, tzinfo=timezone.utc
    )
    assert query.end == datetime(  # noqa: S101
        2026, 11, 24, 8, 0, 1, tzinfo=timezone.utc
    )


@pytest.mark.parametrize(
    ("signatures", "reason"),
    [
        (
            [
                {"type": "start_date", "value": "2026-11-24T08:00:00Z"},
                {"type": "parent_process_name", "value": MARKER},
            ],
            "no end_date",
        ),
        (
            [
                {"type": "end_date", "value": "2026-11-24T09:00:00Z"},
                {"type": "parent_process_name", "value": MARKER},
            ],
            "no start_date",
        ),
        (
            _signatures(parent_process_name=MARKER, start_date="soon"),
            "start_date or end_date is not a valid date",
        ),
        (
            _signatures(
                parent_process_name=MARKER,
                start_date="2026-11-24T10:00:00Z",
                end_date="2026-11-24T09:00:00Z",
            ),
            "start_date is after end_date",
        ),
        (
            _signatures(
                parent_process_name=MARKER,
                start_date="2026-11-24T08:00:00.900Z",
                end_date="2026-11-24T08:00:00.100Z",
            ),
            "start_date is after end_date",
        ),
        (
            _signatures(
                parent_process_name=MARKER,
                start_date="2026-11-24T08:00:00.9000001Z",
                end_date="2026-11-24T08:00:00.9000000Z",
            ),
            "start_date is after end_date",
        ),
        (_signatures(), "no marker and no IP"),
    ],
    ids=[
        "no-end",
        "no-start",
        "invalid-date",
        "start-after-end",
        "start-after-end-in-the-same-second",
        "start-after-end-by-100-nanoseconds",
        "no-signal",
    ],
)
def test_unsearchable_expectation_gives_the_reason(signatures, reason):
    """An expectation that cannot be searched gives a reason, never a filter."""
    # Act
    query = build_logging_query(signatures, self_hosted=False)

    # Assert
    assert query == Unqueryable(reason)  # noqa: S101
