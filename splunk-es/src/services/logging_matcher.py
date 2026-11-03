"""Splunk ES Logging matcher.

This module decides whether the raw log events returned by the Logging
search record an inject: one event inside the inject window that contains
the inject marker or one of its source or target IPs is enough.
"""

import logging
from dataclasses import dataclass
from typing import Sequence

from pyoaev.apis.inject_expectation_trace import (  # type: ignore[import-untyped]
    TraceMatchType,
)

from .logging_query import LoggingQuery, Unqueryable
from .models import LoggingEvent
from .utils.regex_engine import RegexSignatureEngine, Signature

LOG_PREFIX = "[SplunkESLoggingMatcher]"

# Strongest signal first: the marker identifies the inject itself, while an
# IP only identifies a host, which may have logged unrelated activity.
MATCH_TYPE_PRIORITY: tuple[TraceMatchType, ...] = (
    TraceMatchType.MARKER,
    TraceMatchType.SOURCE_IP,
    TraceMatchType.TARGET_IP,
)

# Characters each IP family is written with, and its digits (separators
# excluded). Dots belong to IPv6 too, for the IPv4-mapped form.
_IPV4_CHARS = frozenset("0123456789.")
_IPV4_DIGITS = frozenset("0123456789")
_IPV6_CHARS = frozenset("0123456789abcdef:.")
_IPV6_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Match:
    """An event of the inject window records the inject.

    Attributes:
        match_type: Strongest signal found in the event.
        event: The chosen event.

    """

    match_type: TraceMatchType
    event: LoggingEvent


@dataclass(frozen=True)
class NoMatch:
    """No event of the inject window contains any signal of the search."""


LoggingMatchResult = Match | NoMatch | Unqueryable


class LoggingMatcher:
    """Match raw log events against the signals of a Logging search.

    Signals are searched as literals in each event's raw text with the
    raw-text regex signature engine, in OR mode. An IP must also be a whole
    address in the text, so that ``10.0.0.1`` is not found inside
    ``10.0.0.12``. ``match`` returns ``Unqueryable`` for a search whose
    values are all blank, not only when it is given one.

    When several events match, the strongest signal wins (marker, then
    source IP, then target IP), even over an earlier event; among events with
    the same signal, the earliest one is chosen.
    """

    def __init__(self, engine: RegexSignatureEngine | None = None) -> None:
        """Initialize the matcher.

        Args:
            engine: Signature engine to use; a default one is created when
                omitted.

        """
        self.logger = logging.getLogger(__name__)
        self._engine = engine or RegexSignatureEngine()

    def match(
        self, query: LoggingQuery | Unqueryable, events: Sequence[LoggingEvent]
    ) -> LoggingMatchResult:
        """Find the event that best records the inject.

        Args:
            query: The Logging search of the expectation, or why there is
                none (returned unchanged).
            events: Events returned by the Logging search.

        Returns:
            ``Match`` with the strongest signal and its event, ``NoMatch``
            when no event of the window contains a signal, or
            ``Unqueryable`` when the search has no signal at all.

        """
        if isinstance(query, Unqueryable):
            return query

        signatures = self._signatures(query)
        if not signatures:
            # Every event would match an empty literal: never guess.
            return Unqueryable("no marker and no IP")

        best: Match | None = None
        outside_window = 0
        for event in events:
            if not query.earliest <= event.event_epoch <= query.latest:
                outside_window += 1
                continue
            match_type = self._strongest_signal(event, signatures)
            if match_type is None:
                continue
            candidate = Match(match_type=match_type, event=event)
            if best is None or self._rank(candidate) < self._rank(best):
                best = candidate

        self.logger.debug(
            f"{LOG_PREFIX} Checked {len(events)} events "
            f"({outside_window} outside the window): "
            f"{best.match_type.value if best else 'no match'}"
        )
        return best or NoMatch()

    def _signatures(self, query: LoggingQuery) -> list[Signature]:
        """Build one engine signature per signal of the search.

        Args:
            query: The Logging search.

        Returns:
            The marker signature (with its alternates) when there is a
            marker, then one signature per source and target IP. Blank
            values are dropped.

        """
        signatures: list[Signature] = []
        marker_values = [value for value in query.marker_values if value.strip()]
        if marker_values:
            signatures.append(
                Signature(
                    type=TraceMatchType.MARKER.value,
                    value=marker_values[0],
                    alternates=tuple(marker_values[1:]),
                )
            )
        for match_type, ips in (
            (TraceMatchType.SOURCE_IP, query.source_ips),
            (TraceMatchType.TARGET_IP, query.target_ips),
        ):
            signatures.extend(
                Signature(type=match_type.value, value=ip.strip())
                for ip in ips
                if ip.strip()
            )
        return signatures

    def _strongest_signal(
        self, event: LoggingEvent, signatures: list[Signature]
    ) -> TraceMatchType | None:
        """Return the strongest signal found in one event.

        Args:
            event: The event to search.
            signatures: Signatures of the search.

        Returns:
            The strongest match type found, or ``None``.

        """
        raw_text = self._engine.raw_text_from(event.raw)
        if not raw_text:
            return None
        result = self._engine.evaluate(raw_text, signatures)
        found = {
            match.signature.type
            for match in result.matches
            if match.found and self._confirmed(match.signature, raw_text)
        }
        for match_type in MATCH_TYPE_PRIORITY:
            if match_type.value in found:
                return match_type
        return None

    def _confirmed(self, signature: Signature, raw_text: str) -> bool:
        """Check that a found IP is a whole address, not part of a longer one.

        Args:
            signature: A signature the engine found.
            raw_text: The event's raw text.

        Returns:
            ``True`` for the marker; for an IP, whether one occurrence of it
            is a whole address (see ``_is_whole_address``).

        """
        if signature.type == TraceMatchType.MARKER.value:
            return True
        return _is_whole_address(raw_text.lower(), signature.value.lower())

    @staticmethod
    def _rank(match: Match) -> tuple[int, float]:
        """Order matches: strongest signal first, then earliest event.

        Args:
            match: A candidate match.

        Returns:
            Sort key, lower is better.

        """
        return MATCH_TYPE_PRIORITY.index(match.match_type), match.event.event_epoch


def _is_whole_address(text: str, ip: str) -> bool:
    """Check that an IP occurs in the text as a whole address.

    An occurrence is rejected when address characters next to it make it part
    of a longer address: digits glued to it (``10.0.0.1`` in ``10.0.0.12``,
    ``2001:db8::1`` in ``2001:db8::12``), or a separator followed by more
    digits (``1.10.0.0.1``, ``10.0.0.1.5``, ``de:2001:db8::1``). Those digits
    are only a label when a word goes on past them (``outside:2001:db8::1``,
    ``host1.10.0.0.1``). A port or trailing punctuation is accepted
    (``10.0.0.1:443``, ``[2001:db8::1]:443``, ``10.0.0.1.``).

    Args:
        text: Lowercase event text.
        ip: Lowercase IPv4 or IPv6 address.

    Returns:
        Whether at least one occurrence of the IP is a whole address.

    """
    if ":" in ip:
        chars, digits = _IPV6_CHARS, _IPV6_DIGITS
    else:
        chars, digits = _IPV4_CHARS, _IPV4_DIGITS
    start = text.find(ip)
    while start != -1:
        end = start + len(ip)
        if not _extends(text, start - 1, -1, chars, digits) and not _extends(
            text, end, 1, chars, digits
        ):
            return True
        start = text.find(ip, start + 1)
    return False


def _extends(
    text: str, index: int, step: int, chars: frozenset[str], digits: frozenset[str]
) -> bool:
    """Check whether the characters on one side of an occurrence extend it.

    Args:
        text: Lowercase event text.
        index: Position right next to the occurrence.
        step: ``-1`` to look left, ``1`` to look right.
        chars: Characters an address of this family is written with.
        digits: Digits of this family (separators excluded).

    Returns:
        Whether the address characters on that side make the occurrence part
        of a longer address.

    """
    run = ""
    while 0 <= index < len(text) and text[index] in chars:
        run += text[index]
        index += step
    if not run or not any(char in digits for char in run):
        return False
    if run[0] in digits:
        return True
    # Separator then digits: a longer address, unless a word goes on past them.
    beyond = text[index] if 0 <= index < len(text) else ""
    return not (beyond.isalnum() or beyond == "_")
