"""Tests for query template resolution in Splunk ES Client API."""

from unittest.mock import Mock, patch

import pytest

from src.services.client_api import (
    ALLOWED_PLACEHOLDERS,
    DEFAULT_QUERY_TEMPLATE,
    SplunkESClientAPI,
)
from src.services.exception import SplunkESValidationError
from src.services.models import SplunkESSearchCriteria
from tests.services.fixtures.factories import create_test_config


class TestQueryTemplateResolution:
    """Test cases for SPL query template resolution.

    Verifies that the query template mechanism correctly resolves placeholders,
    falls back to defaults, and validates query structure.
    """

    def _create_client(self, query_template=None):
        """Create a SplunkESClientAPI instance with optional custom query template.

        Args:
            query_template: Optional custom SPL query template.

        Returns:
            SplunkESClientAPI instance configured for testing.

        """
        config = create_test_config()
        if query_template is not None:
            config.splunk_es.query_template = query_template
        else:
            config.splunk_es.query_template = None
        return SplunkESClientAPI(config=config)

    def test_default_template_produces_valid_query(self):
        """Test that the default template resolves to a valid SPL query.

        Verifies backward compatibility: when no custom template is configured,
        the output matches the expected format with all standard fields.
        """
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100"],
            target_ips=["10.0.0.50"],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert "index=" in result
        assert "| table _time" in result
        assert "| sort -_time" in result
        assert 'src_ip IN ("192.168.1.100")' in result
        assert 'dst_ip IN ("10.0.0.50")' in result
        assert "earliest=-" in result

    def test_default_template_with_no_conditions(self):
        """Test default template with empty search criteria.

        Verifies that empty IP/process conditions result in a clean query
        without orphan parentheses or extra whitespace.
        """
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=[],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert "index=" in result
        assert "| table _time" in result
        assert "()" not in result
        # No double spaces
        assert "  " not in result

    def test_custom_template_resolves_placeholders(self):
        """Test that a custom template correctly resolves all placeholders."""
        custom_template = (
            "index={alerts_index} sourcetype=notable {ip_conditions} "
            "{process_conditions} earliest=-{time_window}s "
            "| table _time, src_ip, dst_ip | sort -_time"
        )
        client = self._create_client(query_template=custom_template)
        criteria = SplunkESSearchCriteria(
            source_ips=["10.0.0.1"],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert "sourcetype=notable" in result
        assert "src_ip=10.0.0.1" in result
        assert "| table _time, src_ip, dst_ip" in result

    def test_empty_template_falls_back_to_default(self):
        """Test that an empty string template falls back to the default."""
        client = self._create_client(query_template="")
        criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.1"],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        # Should use default template (contains full table list)
        assert "signature" in result
        assert "rule_name" in result
        assert "severity" in result

    def test_none_template_falls_back_to_default(self):
        """Test that None template falls back to the default."""
        client = self._create_client(query_template=None)
        criteria = SplunkESSearchCriteria(
            source_ips=[],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert "| table _time" in result
        assert "| sort -_time" in result

    @patch("logging.getLogger")
    def test_missing_table_pipe_logs_warning(self, mock_get_logger):
        """Test that a template without '| table' triggers a warning log."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        custom_template = "index={alerts_index} {ip_conditions} {process_conditions} earliest=-{time_window}s"
        client = self._create_client(query_template=custom_template)
        criteria = SplunkESSearchCriteria(
            source_ips=[],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        client._build_spl_query(criteria)

        mock_logger.warning.assert_called()
        warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
        assert any("| table" in call for call in warning_calls)

    def test_time_window_includes_extend_seconds(self):
        """Test that extend_end_seconds is added to the time window."""
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=[],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        # Default time_window is 1h = 3600s, extend by 60s
        result = client._build_spl_query(criteria, extend_end_seconds=60)

        assert "earliest=-3660s" in result

    def test_multiple_source_ips_in_conditions(self):
        """Test that multiple source IPs are ORed together."""
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=["10.0.0.1", "10.0.0.2"],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert '"10.0.0.1","10.0.0.2"' in result
        assert "src_ip IN" in result
        assert " OR " in result

    def test_source_and_target_ips_combined(self):
        """Test that both source and target IPs appear in conditions."""
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.1"],
            target_ips=["10.0.0.5"],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert 'src_ip IN ("192.168.1.1")' in result
        assert 'dst_ip IN ("10.0.0.5")' in result

    def test_start_end_date_from_signatures(self):
        """Test that start_date/end_date from signatures replace relative time."""
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=["10.0.0.1"],
            target_ips=[],
            parent_process_names=[],
            start_date="2026-06-12T08:00:00Z",
            end_date="2026-06-12T09:00:00Z",
        )

        result = client._build_spl_query(criteria)

        assert "earliest=2026-06-12T08:00:00Z" in result
        assert "latest=2026-06-12T09:00:00Z" in result
        assert "earliest=-" not in result

    def test_start_date_only_fallback_end_to_now(self):
        """Test that missing end_date falls back to 'now'."""
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=["10.0.0.1"],
            target_ips=[],
            parent_process_names=[],
            start_date="2026-06-12T08:00:00Z",
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert "earliest=2026-06-12T08:00:00Z" in result
        assert "latest=now" in result

    def test_no_dates_fallback_to_time_window(self):
        """Test that missing start_date/end_date uses relative time window."""
        client = self._create_client()
        criteria = SplunkESSearchCriteria(
            source_ips=["10.0.0.1"],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        result = client._build_spl_query(criteria)

        assert "earliest=-3600s" in result
        assert "latest=now" in result

    def test_default_query_template_constant_format(self):
        """Test that DEFAULT_QUERY_TEMPLATE has the expected placeholders."""
        assert "{alerts_index}" in DEFAULT_QUERY_TEMPLATE
        assert "{source_ips}" in DEFAULT_QUERY_TEMPLATE
        assert "{target_ips}" in DEFAULT_QUERY_TEMPLATE
        assert "{process_conditions}" in DEFAULT_QUERY_TEMPLATE
        assert "{start_date}" in DEFAULT_QUERY_TEMPLATE
        assert "{end_date}" in DEFAULT_QUERY_TEMPLATE
        assert "| table _time" in DEFAULT_QUERY_TEMPLATE
        assert "| sort -_time" in DEFAULT_QUERY_TEMPLATE
        assert "IN" in DEFAULT_QUERY_TEMPLATE

    def test_custom_template_with_subset_of_placeholders(self):
        """Test a template that only uses some placeholders."""
        custom_template = (
            "index={alerts_index} earliest=-{time_window}s "
            "| table _time, src_ip, dst_ip | sort -_time"
        )
        client = self._create_client(query_template=custom_template)
        criteria = SplunkESSearchCriteria(
            source_ips=["10.0.0.1"],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

        # Should not raise even though {ip_conditions} and {process_conditions} are absent
        result = client._build_spl_query(criteria)

        assert "index=_notable" in result
        assert "earliest=-3600s" in result
        # ip_conditions placeholder not in template, so IPs won't appear
        assert "src_ip=10.0.0.1" not in result


class TestQueryTemplateSecurity:
    """Security tests for query template resolution.

    Verifies that the template engine prevents attribute traversal
    and other format string injection attacks.
    """

    def _create_client(self, query_template=None):
        """Create a test client with optional custom template."""
        config = create_test_config()
        config.splunk_es.query_template = query_template
        return SplunkESClientAPI(config=config)

    def _empty_criteria(self):
        """Return empty search criteria for security tests."""
        return SplunkESSearchCriteria(
            source_ips=[],
            target_ips=[],
            parent_process_names=[],
            start_date=None,
            end_date=None,
        )

    def test_attribute_traversal_blocked(self):
        """Test that {value.__class__} attribute access is rejected."""
        malicious_template = "index={alerts_index.__class__} | table _time"
        client = self._create_client(query_template=malicious_template)

        with pytest.raises(
            SplunkESValidationError, match="Attribute/index access not allowed"
        ):
            client._build_spl_query(self._empty_criteria())

    def test_index_access_blocked(self):
        """Test that {value[0]} index access is rejected."""
        malicious_template = "index={alerts_index[0]} | table _time"
        client = self._create_client(query_template=malicious_template)

        with pytest.raises(
            SplunkESValidationError, match="Attribute/index access not allowed"
        ):
            client._build_spl_query(self._empty_criteria())

    def test_nested_attribute_blocked(self):
        """Test that deep attribute chains are rejected."""
        malicious_template = "{alerts_index.__class__.__subclasses__} | table _time"
        client = self._create_client(query_template=malicious_template)

        with pytest.raises(
            SplunkESValidationError, match="Attribute/index access not allowed"
        ):
            client._build_spl_query(self._empty_criteria())

    def test_unknown_placeholder_raises_error(self):
        """Test that unknown placeholder names raise a validation error."""
        bad_template = "index={unknown_field} | table _time"
        client = self._create_client(query_template=bad_template)

        with pytest.raises(SplunkESValidationError, match="Invalid query template"):
            client._build_spl_query(self._empty_criteria())

    def test_allowed_placeholders_constant(self):
        """Verify DEFAULT_QUERY_TEMPLATE only uses allowed placeholders."""
        import string

        parsed = string.Formatter().parse(DEFAULT_QUERY_TEMPLATE)
        template_fields = {fname for _, fname, _, _ in parsed if fname is not None}
        assert template_fields.issubset(ALLOWED_PLACEHOLDERS)
