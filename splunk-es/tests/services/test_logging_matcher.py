"""Tests for the Splunk ES Logging matcher."""

from pyoaev.apis.inject_expectation_trace import TraceMatchType
from src.services.logging_matcher import LoggingMatcher, Match, NoMatch
from src.services.logging_query import LoggingQuery, Unqueryable
from src.services.models import LoggingEvent
from src.services.utils.parent_process_parser import ParentProcessParser

INJECT_UUID = "877b423b-ae91-4fc5-86c3-fa8ea3c938ba"
AGENT_UUID = "1402422f-2eaa-4fbd-80b2-b30df1b83b19"
MARKER = f"oaev-implant-{INJECT_UUID}-agent-{AGENT_UUID}"
MARKER_URL = ParentProcessParser().build_url_path(INJECT_UUID, AGENT_UUID)
SOURCE_IP = "192.168.1.100"
TARGET_IP = "10.0.0.50"
EARLIEST = 1_761_900_000
LATEST = EARLIEST + 3600


def _query(
    marker_values: list[str] | None = None,
    source_ips: list[str] | None = None,
    target_ips: list[str] | None = None,
) -> LoggingQuery:
    """Build a Logging search over the test window."""
    return LoggingQuery(
        spl="search index IN (main) ...",
        marker_values=[MARKER, MARKER_URL] if marker_values is None else marker_values,
        source_ips=[SOURCE_IP] if source_ips is None else source_ips,
        target_ips=[TARGET_IP] if target_ips is None else target_ips,
        earliest=EARLIEST,
        latest=LATEST,
    )


def _event(raw: str, offset: float = 60, index: str = "sysmon") -> LoggingEvent:
    """Build an event `offset` seconds after the start of the test window."""
    return LoggingEvent(
        event_epoch=EARLIEST + offset, index=index, host="ws-01", raw=raw
    )


def _match(query: LoggingQuery | Unqueryable, events: list[LoggingEvent]):
    return LoggingMatcher().match(query, events)


class TestLoggingMatcherSignals:
    """Each signal alone is enough, and is reported with its match type."""

    def test_marker_only(self):
        event = _event(f"ParentImage=C:\\oaev\\{MARKER}.exe")

        result = _match(_query(), [event])

        assert result == Match(match_type=TraceMatchType.MARKER, event=event)

    def test_url_alternate_only_counts_as_marker(self):
        event = _event(f"GET {MARKER_URL} HTTP/1.1")

        result = _match(_query(), [event])

        assert result == Match(match_type=TraceMatchType.MARKER, event=event)

    def test_source_ip_only(self):
        event = _event(f"src={SOURCE_IP} action=allowed")

        result = _match(_query(), [event])

        assert result == Match(match_type=TraceMatchType.SOURCE_IP, event=event)

    def test_target_ip_only(self):
        event = _event(f"dest={TARGET_IP}:445 action=allowed")

        result = _match(_query(), [event])

        assert result == Match(match_type=TraceMatchType.TARGET_IP, event=event)

    def test_marker_matches_case_insensitively(self):
        event = _event(f"Image={MARKER.upper()}.EXE")

        result = _match(_query(), [event])

        assert isinstance(result, Match)
        assert result.match_type == TraceMatchType.MARKER


class TestLoggingMatcherPriority:
    """The strongest signal wins: marker, then source IP, then target IP."""

    def test_marker_and_ip_on_the_same_event_is_marker(self):
        event = _event(f"src={SOURCE_IP} dest={TARGET_IP} Image={MARKER}.exe")

        result = _match(_query(), [event])

        assert result == Match(match_type=TraceMatchType.MARKER, event=event)

    def test_later_marker_event_wins_over_earlier_ip_event(self):
        ip_event = _event(f"src={SOURCE_IP}", offset=10)
        marker_event = _event(f"Image={MARKER}.exe", offset=900)

        result = _match(_query(), [ip_event, marker_event])

        assert result == Match(match_type=TraceMatchType.MARKER, event=marker_event)

    def test_source_ip_wins_over_target_ip_across_events(self):
        target_event = _event(f"dest={TARGET_IP}", offset=10)
        source_event = _event(f"src={SOURCE_IP}", offset=20)

        result = _match(_query(), [target_event, source_event])

        assert result == Match(match_type=TraceMatchType.SOURCE_IP, event=source_event)

    def test_earliest_event_wins_for_the_same_signal(self):
        later = _event(f"Image={MARKER}.exe", offset=900)
        earlier = _event(f"Image={MARKER}.exe", offset=30)

        result = _match(_query(), [later, earlier])

        assert result == Match(match_type=TraceMatchType.MARKER, event=earlier)


class TestLoggingMatcherNoMatch:
    """Events that do not record the inject never produce a match."""

    def test_no_signal_in_any_event(self):
        events = [_event("user=alice action=logon"), _event("process=notepad.exe")]

        assert _match(_query(), events) == NoMatch()

    def test_empty_event_list(self):
        assert _match(_query(), []) == NoMatch()

    def test_marker_outside_the_window_does_not_beat_an_ip_inside(self):
        ip_event = _event(f"src={SOURCE_IP}", offset=10)
        late_marker = _event(f"Image={MARKER}.exe", offset=3601)

        result = _match(_query(), [ip_event, late_marker])

        assert result == Match(match_type=TraceMatchType.SOURCE_IP, event=ip_event)

    def test_events_outside_the_window_are_ignored(self):
        before = _event(f"Image={MARKER}.exe", offset=-1)
        after = _event(f"Image={MARKER}.exe", offset=3601)

        assert _match(_query(), [before, after]) == NoMatch()

    def test_event_at_the_start_of_the_window_is_kept(self):
        at_start = _event(f"Image={MARKER}.exe", offset=0)

        result = _match(_query(), [at_start])

        assert result == Match(match_type=TraceMatchType.MARKER, event=at_start)

    def test_event_at_the_end_of_the_window_is_kept(self):
        at_end = _event(f"Image={MARKER}.exe", offset=3600)

        result = _match(_query(), [at_end])

        assert result == Match(match_type=TraceMatchType.MARKER, event=at_end)

    def test_hostname_only_is_not_a_match(self):
        # The search carries no hostname signal: a host name alone never counts.
        event = _event("host=ws-01 ComputerName=ws-01.corp.example")

        assert _match(_query(), [event]) == NoMatch()

    def test_event_with_empty_raw_text(self):
        assert _match(_query(), [_event("")]) == NoMatch()


class TestLoggingMatcherLiterals:
    """Values are matched as literals, and IPs as whole addresses."""

    def test_regex_metacharacters_in_marker_are_literal(self):
        marker = "evil.(exe)+[1]"
        query = _query(marker_values=[marker], source_ips=[], target_ips=[])

        assert _match(query, [_event("evilX(exe)1")]) == NoMatch()
        assert isinstance(_match(query, [_event(f"Image={marker}")]), Match)

    def test_non_ascii_marker(self):
        marker = "implant-café-Ünïcode"
        query = _query(marker_values=[marker], source_ips=[], target_ips=[])

        result = _match(query, [_event(f"Image=C:\\{marker}.exe")])

        assert isinstance(result, Match)
        assert result.match_type == TraceMatchType.MARKER

    def test_ipv4_inside_a_longer_address_is_not_a_match(self):
        query = _query(marker_values=[], source_ips=["10.0.0.1"], target_ips=[])

        events = [
            _event("src=10.0.0.12"),
            _event("src=10.0.0.12x"),
            _event("src=110.0.0.1"),
            _event("src=10.0.0.1.5"),
        ]

        assert _match(query, events) == NoMatch()

    def test_ipv4_followed_by_a_port_or_a_dot_is_a_match(self):
        query = _query(marker_values=[], source_ips=["10.0.0.1"], target_ips=[])

        assert isinstance(_match(query, [_event("src=10.0.0.1:443")]), Match)
        assert isinstance(_match(query, [_event("from 10.0.0.1.")]), Match)

    def test_ipv6(self):
        query = _query(marker_values=[], source_ips=["2001:db8::1"], target_ips=[])

        assert isinstance(_match(query, [_event("src=[2001:DB8::1]:443")]), Match)
        assert _match(query, [_event("src=2001:db8::12")]) == NoMatch()

    def test_ipv4_mapped_ipv6(self):
        query = _query(marker_values=[], source_ips=["::ffff:10.0.0.1"], target_ips=[])

        assert isinstance(_match(query, [_event("src=::FFFF:10.0.0.1 ok")]), Match)
        assert _match(query, [_event("src=::ffff:10.0.0.12")]) == NoMatch()
        assert _match(query, [_event("src=::ffff:10.0.0.1.5")]) == NoMatch()

    def test_longer_address_on_the_left_is_not_a_match(self):
        ipv4 = _query(marker_values=[], source_ips=["10.0.0.1"], target_ips=[])
        ipv6 = _query(marker_values=[], source_ips=["2001:db8::1"], target_ips=[])

        assert _match(ipv4, [_event("src=1.10.0.0.1")]) == NoMatch()
        assert _match(ipv6, [_event("src=de:2001:db8::1")]) == NoMatch()
        assert _match(ipv6, [_event("src=2001:db8::1:443")]) == NoMatch()

    def test_address_after_a_label_is_a_match(self):
        ipv4 = _query(marker_values=[], source_ips=["10.0.0.1"], target_ips=[])
        ipv6 = _query(marker_values=[], source_ips=["2001:db8::1"], target_ips=[])
        asa = (
            "%ASA-6-302013: Built inbound TCP connection 1 for "
            "outside:{ip}/51000 to inside:{other}/443"
        )

        for event in (
            asa.format(ip="10.0.0.1", other="10.0.0.2"),
            "ip.10.0.0.1",
            "host1.10.0.0.1",
            "10.0.0.1.example.com",
        ):
            assert isinstance(_match(ipv4, [_event(event)]), Match), event
        for event in (
            asa.format(ip="2001:db8::1", other="2001:db8::2"),
            "ip:2001:db8::1",
            "2001:db8::1:admin",
        ):
            assert isinstance(_match(ipv6, [_event(event)]), Match), event

    def test_later_occurrence_is_found_after_a_longer_address(self):
        query = _query(marker_values=[], source_ips=["10.0.0.1"], target_ips=[])

        result = _match(query, [_event("src=10.0.0.12 dst=10.0.0.1")])

        assert isinstance(result, Match)

    def test_blank_values_are_ignored(self):
        # A blank literal would match every event.
        query = _query(marker_values=["", " "], source_ips=[""], target_ips=[TARGET_IP])

        assert _match(query, [_event("user=alice")]) == NoMatch()


class TestLoggingMatcherUnqueryable:
    """A search without any signal is never answered."""

    def test_unqueryable_is_passed_through(self):
        unqueryable = Unqueryable("no end_date")

        assert _match(unqueryable, [_event(f"Image={MARKER}.exe")]) is unqueryable

    def test_search_without_any_signal_is_unqueryable(self):
        query = _query(marker_values=[], source_ips=[], target_ips=[" "])

        result = _match(query, [_event("anything")])

        assert isinstance(result, Unqueryable)
