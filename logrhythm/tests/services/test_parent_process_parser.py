"""Tests for the ParentProcessParser utility."""

from src.services.utils.parent_process_parser import ParentProcessParser

INJECT_UUID = "877b423b-ae91-4fc5-86c3-fa8ea3c938ba"
AGENT_UUID = "1402422f-2eaa-4fbd-80b2-b30df1b83b19"
PARENT_PROCESS_NAME = f"oaev-implant-{INJECT_UUID}-agent-{AGENT_UUID}"
URL_PATH = f"/api/injects/{INJECT_UUID}/{AGENT_UUID}/executable-payload"


class TestParentProcessParser:
    """Test cases for ParentProcessParser."""

    def test_extract_uuids_from_parent_process_name_valid(self):
        """Valid parent process names yield the inject and agent UUIDs."""
        parser = ParentProcessParser()
        result = parser.extract_uuids_from_parent_process_name(PARENT_PROCESS_NAME)
        assert result == (INJECT_UUID, AGENT_UUID)  # noqa: S101

    def test_extract_uuids_from_parent_process_name_empty(self):
        """Empty input returns None."""
        parser = ParentProcessParser()
        assert parser.extract_uuids_from_parent_process_name("") is None  # noqa: S101

    def test_extract_uuids_from_parent_process_name_no_match(self):
        """Non-matching input returns None."""
        parser = ParentProcessParser()
        assert (  # noqa: S101
            parser.extract_uuids_from_parent_process_name("not-a-match") is None
        )

    def test_construct_parent_process_name(self):
        """UUIDs are recombined into the canonical parent process name."""
        parser = ParentProcessParser()
        result = parser.construct_parent_process_name(INJECT_UUID, AGENT_UUID)
        assert result == PARENT_PROCESS_NAME  # noqa: S101

    def test_construct_parent_process_name_missing(self):
        """Missing UUIDs produce an empty string."""
        parser = ParentProcessParser()
        assert parser.construct_parent_process_name("", AGENT_UUID) == ""  # noqa: S101

    def test_extract_uuids_from_url_path_valid(self):
        """Valid URL paths yield the inject and agent UUIDs."""
        parser = ParentProcessParser()
        result = parser.extract_uuids_from_url_path(URL_PATH)
        assert result == (INJECT_UUID, AGENT_UUID)  # noqa: S101

    def test_extract_uuids_from_url_path_empty(self):
        """Empty URL path returns None."""
        parser = ParentProcessParser()
        assert parser.extract_uuids_from_url_path("") is None  # noqa: S101

    def test_extract_uuids_from_url_path_no_match(self):
        """Non-matching URL path returns None."""
        parser = ParentProcessParser()
        assert parser.extract_uuids_from_url_path("/api/other") is None  # noqa: S101

    def test_build_url_path_search_query(self):
        """The search query lists all URL field aliases and the injected path."""
        parser = ParentProcessParser()
        query = parser.build_url_path_search_query(INJECT_UUID, AGENT_UUID)
        assert URL_PATH in query  # noqa: S101
        for field in ("url_path", "url", "path", "query"):
            assert f'{field}="{URL_PATH}"' in query  # noqa: S101

    def test_build_url_path_search_query_missing(self):
        """Missing UUIDs produce an empty query."""
        parser = ParentProcessParser()
        assert parser.build_url_path_search_query("", "") == ""  # noqa: S101

    def test_validate_uuid_format(self):
        """UUID validation accepts valid UUIDs and rejects invalid ones."""
        parser = ParentProcessParser()
        assert parser.validate_uuid_format(INJECT_UUID) is True  # noqa: S101
        assert parser.validate_uuid_format("not-a-uuid") is False  # noqa: S101
        assert parser.validate_uuid_format("") is False  # noqa: S101
