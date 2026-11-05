"""Splunk ES Logging search query types.

This module holds the Logging search built for one LOGGING expectation, or
the reason why no search can be built for it. The Logging matcher and trace
builder read these types; ``build_logging_query`` builds them from the
expectation's signatures.
"""

import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from .utils.epoch import to_epoch, to_epoch_ceil
from .utils.parent_process_parser import ParentProcessParser

MARKER_SIGNATURE_TYPE = "parent_process_name"
SOURCE_IP_SIGNATURE_TYPES = ("source_ipv4_address", "source_ipv6_address")
TARGET_IP_SIGNATURE_TYPES = ("target_ipv4_address", "target_ipv6_address")
START_DATE_SIGNATURE_TYPE = "start_date"
END_DATE_SIGNATURE_TYPE = "end_date"

# The built-in Logging search: a full-text search, so it needs no extracted
# field. SPLUNKES_LOGGING_QUERY_TEMPLATE can replace it. Events are ranked like
# the matcher ranks signals (marker, then source IP), so the row cap never drops
# a stronger event behind weaker ones.
LOGGING_QUERY_TEMPLATE = (
    "search index IN ({indexes}) earliest={earliest} latest={latest} ({terms})"
    " | eval oaev_rank=case({rank_cases})"
    " | sort {max_rows} -oaev_rank, +_time"
    " | eval oaev_event_epoch=_time"
    " | table oaev_event_epoch, index, host, sourcetype, _raw"
)
MARKER_RANK = 2
SOURCE_IP_RANK = 1


@dataclass(frozen=True)
class LoggingQuery:
    """Logging search for one LOGGING expectation.

    Attributes:
        spl: The SPL search sent to Splunk, also used in trace links.
        marker_values: The parent process name signature value first,
            followed by its implant callback URL alternates. Empty when the
            expectation has no marker.
        source_ips: Source IPv4 and IPv6 signature values.
        target_ips: Target IPv4 and IPv6 signature values.
        earliest: Start of the inject window, Unix epoch seconds, inclusive.
        latest: End of the inject window, Unix epoch seconds, inclusive.

    """

    spl: str
    marker_values: list[str]
    source_ips: list[str]
    target_ips: list[str]
    earliest: int
    latest: int


@dataclass(frozen=True)
class Unqueryable:
    """No Logging search can be built for an expectation.

    Attributes:
        reason: Why the expectation cannot be searched (e.g. no end date,
            no marker and no IP).

    """

    reason: str


def build_logging_query(
    signatures: Iterable[Mapping[str, str]],
    indexes: list[str],
    max_rows: int,
    template: str | None = None,
) -> LoggingQuery | Unqueryable:
    """Build the Logging search of one LOGGING expectation.

    The built-in search looks in the raw-event indexes, inside the inject
    window, for events that contain the marker (or its callback URL) OR one of
    the source or target IPs. The host name is not a signal: Splunk's ``host``
    is often the log forwarder, not the machine that ran the inject.

    Args:
        signatures: The expectation's signatures, as ``{"type", "value"}``
            mappings.
        indexes: Raw-event index names, ``*`` wildcards allowed. Each name
            is quoted in the search, so it cannot change its meaning.
        max_rows: Maximum number of events the search returns.
        template: A custom search (``SPLUNKES_LOGGING_QUERY_TEMPLATE``),
            already checked by the config, or None for the built-in one.

    Returns:
        The search, or ``Unqueryable`` when the expectation has no end date,
        no valid window, or neither a marker nor an IP.

    """
    by_type: dict[str, list[str]] = {}
    for signature in signatures:
        value = str(signature.get("value") or "").strip()
        if value:
            by_type.setdefault(str(signature.get("type")), []).append(value)

    if not indexes:
        return Unqueryable("no Logging index configured")

    end_dates = by_type.get(END_DATE_SIGNATURE_TYPE, [])
    if not end_dates:
        return Unqueryable("no end_date")
    start_dates = by_type.get(START_DATE_SIGNATURE_TYPE, [])
    if not start_dates:
        return Unqueryable("no start_date")
    # Round the window outwards: it can only grow by under a second, never
    # lose the end of the inject (the matcher compares exact event times).
    earliest = to_epoch(start_dates[0])
    latest = to_epoch_ceil(end_dates[0])
    if earliest is None or latest is None:
        return Unqueryable("start_date or end_date is not a valid date")
    if earliest > latest:
        return Unqueryable("start_date is after end_date")

    marker_values = _marker_values(by_type.get(MARKER_SIGNATURE_TYPE, []))
    source_ips = _unique(
        ip for kind in SOURCE_IP_SIGNATURE_TYPES for ip in by_type.get(kind, [])
    )
    target_ips = _unique(
        ip for kind in TARGET_IP_SIGNATURE_TYPES for ip in by_type.get(kind, [])
    )
    if not marker_values and not source_ips and not target_ips:
        # Never search without a signal: it would match every event.
        return Unqueryable("no marker and no IP")

    terms = " OR ".join(
        spl_string(value)
        for value in _unique([*marker_values, *source_ips, *target_ips])
    )
    spl = (template or LOGGING_QUERY_TEMPLATE).format_map(
        {
            "indexes": ",".join(spl_string(index) for index in indexes),
            "earliest": earliest,
            # Splunk's latest is exclusive; the window's end is inclusive.
            "latest": latest + 1,
            "terms": terms,
            "source_ips": _quoted_list(source_ips),
            "target_ips": _quoted_list(target_ips),
            "rank_cases": _rank_cases(marker_values, source_ips),
            "max_rows": max_rows,
        }
    )
    # The search API needs a generating command first; a custom template may
    # be written like the Detection one, without it.
    if not spl.lstrip().startswith(("search ", "|")):
        spl = f"search {spl}"
    return LoggingQuery(
        spl=spl,
        marker_values=marker_values,
        source_ips=source_ips,
        target_ips=target_ips,
        earliest=earliest,
        latest=latest,
    )


def _marker_values(markers: list[str]) -> list[str]:
    """List the marker first, then its implant callback URL alternates.

    A network event never carries the implant's process name, only its
    callback URL, which embeds the same inject and agent IDs.

    Args:
        markers: Parent process name signature values.

    Returns:
        The first marker followed by the callback URL of each marker, without
        duplicates. Empty when there is no marker.

    """
    if not markers:
        return []
    parser = ParentProcessParser()
    values = [markers[0]]
    for marker in markers:
        uuids = parser.extract_uuids_from_parent_process_name(marker)
        if uuids:
            values.append(parser.build_url_path(*uuids))
    return _unique(values)


def _quoted_list(values: list[str]) -> str:
    """Write values as a quoted, comma-separated list for SPL ``IN (...)``.

    An empty list gives ``""``, which matches nothing, so a template such as
    ``src_ip IN ({source_ips})`` never turns into "any source IP".
    """
    if not values:
        return '""'
    return ",".join(spl_string(value) for value in values)


def _unique(values: Iterable[str]) -> list[str]:
    """Drop blank values and duplicates, keeping the first occurrence order."""
    return list(dict.fromkeys(value for value in values if value))


def _rank_cases(marker_values: list[str], source_ips: list[str]) -> str:
    """Write the ``case()`` arguments that rank an event like the matcher.

    An event with the marker ranks first, then one with a source IP, then
    every other event (target IP only).
    """
    cases: list[str] = []
    if marker_values:
        cases += [_contains_any(marker_values), str(MARKER_RANK)]
    if source_ips:
        cases += [_contains_any(source_ips), str(SOURCE_IP_RANK)]
    return ", ".join([*cases, "1=1", "0"])


def _contains_any(values: list[str]) -> str:
    """Write a case-insensitive SPL test: "the raw text contains one of these"."""
    pattern = "|".join(re.escape(value.lower()) for value in values)
    return f"match(lower(_raw), {spl_string(pattern)})"


def spl_string(value: str) -> str:
    r"""Write a value as a double-quoted SPL string.

    Backslashes are escaped first, then double quotes, so a value cannot
    close the string and inject SPL (``a"b\c`` becomes ``"a\"b\\c"``).
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
