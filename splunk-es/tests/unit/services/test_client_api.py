import unittest
from unittest.mock import MagicMock, ANY, patch, sentinel

import src.services.client_api as module


class TestSplunkESClientAPI(unittest.TestCase):
    @patch.object(module.SplunkESClientAPI, "_validate_template_placeholders")
    @patch.object(module.SplunkESClientAPI, "_create_session")
    def test_init_minimal_config(self, m_create_session, m_validate_template_placeholders):
        config = MagicMock()
        config_splunk_es = MagicMock()
        base_url = MagicMock()
        config_splunk_es.base_url = base_url
        config_splunk_es.username = sentinel.username
        password = MagicMock()
        config_splunk_es.password = password
        config_splunk_es.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_splunk_es.offset = offset
        config_splunk_es.max_retry = sentinel.max_retry
        config_splunk_es.time_window = None
        config_splunk_es.query_template = None
        config.splunk_es = config_splunk_es

        client_api = module.SplunkESClientAPI(config)

        self.assertEqual(client_api.base_url, str(base_url).rstrip("/"))
        self.assertEqual(client_api.username, sentinel.username)
        self.assertEqual(client_api.password, password.get_secret_value.return_value)
        self.assertEqual(client_api.alerts_index, sentinel.alerts_index)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.time_window, module.timedelta(hours=module.DEFAULT_TIME_WINDOW_HOURS))
        self.assertEqual(client_api.query_template, module.DEFAULT_QUERY_TEMPLATE)
        m_validate_template_placeholders.assert_not_called()
        m_create_session.assert_called_once()
        self.assertEqual(client_api.session, m_create_session.return_value)

    @patch.object(module.SplunkESClientAPI, "_validate_template_placeholders")
    @patch.object(module.SplunkESClientAPI, "_create_session")
    def test_init_full_config(self, m_create_session, m_validate_template_placeholders):
        config = MagicMock()
        config_splunk_es = MagicMock()
        base_url = MagicMock()
        config_splunk_es.base_url = base_url
        config_splunk_es.username = sentinel.username
        password = MagicMock()
        config_splunk_es.password = password
        config_splunk_es.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_splunk_es.offset = offset
        config_splunk_es.max_retry = sentinel.max_retry
        config_splunk_es.time_window = sentinel.time_window
        config_splunk_es.query_template = sentinel.query_template
        config.splunk_es = config_splunk_es

        client_api = module.SplunkESClientAPI(config)

        self.assertEqual(client_api.base_url, str(base_url).rstrip("/"))
        self.assertEqual(client_api.username, sentinel.username)
        self.assertEqual(client_api.password, password.get_secret_value.return_value)
        self.assertEqual(client_api.alerts_index, sentinel.alerts_index)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.time_window, sentinel.time_window)
        self.assertEqual(client_api.query_template, sentinel.query_template)
        m_validate_template_placeholders.assert_called_with(sentinel.query_template)
        m_create_session.assert_called_once()
        self.assertEqual(client_api.session, m_create_session.return_value)

    @patch.object(module.SplunkESClientAPI, "_execute_splunk_query_with_retry")
    @patch.object(module.SplunkESClientAPI, "_build_search_criteria")
    @patch.object(module.SplunkESClientAPI, "_validate_template_placeholders")
    @patch.object(module.SplunkESClientAPI, "_create_session")
    def test_fetch_signatures(self, m_create_session, m_validate_template_placeholders, m_build_search_criteria, m_execute_splunk_query_with_retry):
        config = MagicMock()
        client_api = module.SplunkESClientAPI(config)

        search_signatures = MagicMock()
        expectation_type = "detection"

        alert_objects = client_api.fetch_signatures(search_signatures, expectation_type)

        m_build_search_criteria.assert_called_with(search_signatures)
        m_execute_splunk_query_with_retry.assert_called_with(m_build_search_criteria.return_value)
        self.assertEqual(alert_objects, m_execute_splunk_query_with_retry.return_value)

    @patch.object(module.SplunkESClientAPI, "_execute_splunk_query_with_retry")
    @patch.object(module.SplunkESClientAPI, "_build_search_criteria")
    @patch.object(module.SplunkESClientAPI, "_validate_template_placeholders")
    @patch.object(module.SplunkESClientAPI, "_create_session")
    def test_fetch_signatures_not_detection(self, m_create_session, m_validate_template_placeholders, m_build_search_criteria, m_execute_splunk_query_with_retry):
        config = MagicMock()
        client_api = module.SplunkESClientAPI(config)

        search_signatures = MagicMock()
        expectation_type = "prevention"

        with self.assertRaises(module.SplunkESValidationError):
            client_api.fetch_signatures(search_signatures, expectation_type)
            m_build_search_criteria.assert_not_called()
            m_execute_splunk_query_with_retry.assert_not_called()

    @patch.object(module.SplunkESClientAPI, "_execute_splunk_query")
    @patch.object(module.SplunkESClientAPI, "_build_search_criteria")
    @patch.object(module.SplunkESClientAPI, "_validate_template_placeholders")
    @patch.object(module.SplunkESClientAPI, "_create_session")
    def test_fetch_with_retry(self, m_create_session, m_validate_template_placeholders, m_build_search_criteria, m_execute_splunk_query):
        config = MagicMock()
        client_api = module.SplunkESClientAPI(config)

        search_signatures = MagicMock()
        expectation_type = "detection"
        alerts = MagicMock()
        m_execute_splunk_query.return_value = alerts

        alert_objects = client_api.fetch_with_retry(search_signatures, expectation_type)

        m_build_search_criteria.assert_called_with(search_signatures)
        m_execute_splunk_query.assert_called_with(m_build_search_criteria.return_value, 0)
        self.assertEqual(alert_objects, m_execute_splunk_query.return_value)

    @patch.object(module.SplunkESClientAPI, "_execute_splunk_query")
    @patch.object(module.SplunkESClientAPI, "_build_search_criteria")
    @patch.object(module.SplunkESClientAPI, "_validate_template_placeholders")
    @patch.object(module.SplunkESClientAPI, "_create_session")
    def test_fetch_with_retry_not_detection(self, m_create_session, m_validate_template_placeholders, m_build_search_criteria, m_execute_splunk_query):
        config = MagicMock()
        client_api = module.SplunkESClientAPI(config)

        search_signatures = MagicMock()
        expectation_type = "prevention"
        alerts = MagicMock()
        m_execute_splunk_query.return_value = alerts

        with self.assertRaises(module.SplunkESValidationError):
            client_api.fetch_with_retry(search_signatures, expectation_type)

            m_build_search_criteria.assert_not_called()
            m_execute_splunk_query.assert_not_called()
