import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.client_api as module


class TestElasticClientAPI(unittest.TestCase):
    @patch.object(module.ElasticClientAPI, "_create_session")
    def test_init_minimal_config(self, m_create_session):
        config = MagicMock()
        config_elastic = MagicMock()
        base_url = MagicMock()
        config_elastic.base_url = base_url
        config_elastic.api_key = None
        config_elastic.username = sentinel.username
        config_elastic.password = None
        config_elastic.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_elastic.offset = offset
        config_elastic.max_retry = sentinel.max_retry
        config_elastic.verify_ssl = sentinel.verify_ssl
        config_elastic.time_window = None
        config.elastic = config_elastic

        client_api = module.ElasticClientAPI(config)

        self.assertEqual(client_api.base_url, str(base_url).rstrip("/"))
        self.assertIsNone(client_api.api_key)
        self.assertEqual(client_api.username, sentinel.username)
        self.assertIsNone(client_api.password)
        self.assertEqual(client_api.alerts_index, sentinel.alerts_index)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(
            client_api.time_window,
            module.timedelta(hours=module.DEFAULT_TIME_WINDOW_HOURS),
        )
        m_create_session.assert_called_once()
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(
            client_api.parent_process_parser, module.ParentProcessParser
        )

    @patch.object(module.ElasticClientAPI, "_create_session")
    def test_init_full_config(self, m_create_session):
        config = MagicMock()
        config_elastic = MagicMock()
        base_url = MagicMock()
        config_elastic.base_url = base_url
        api_key = MagicMock()
        config_elastic.api_key = api_key
        config_elastic.username = sentinel.username
        password = MagicMock()
        config_elastic.password = password
        config_elastic.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_elastic.offset = offset
        config_elastic.max_retry = sentinel.max_retry
        config_elastic.verify_ssl = sentinel.verify_ssl
        config_elastic.time_window = sentinel.time_window
        config.elastic = config_elastic

        client_api = module.ElasticClientAPI(config)

        self.assertEqual(client_api.base_url, str(base_url).rstrip("/"))
        self.assertEqual(client_api.api_key, api_key.get_secret_value.return_value)
        self.assertEqual(client_api.username, sentinel.username)
        self.assertEqual(client_api.password, password.get_secret_value.return_value)
        self.assertEqual(client_api.alerts_index, sentinel.alerts_index)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(client_api.time_window, sentinel.time_window)
        m_create_session.assert_called_once()
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(
            client_api.parent_process_parser, module.ParentProcessParser
        )

    @patch.object(module, "ElasticResponse")
    @patch.object(module.ElasticClientAPI, "_build_query")
    @patch.object(module.ElasticClientAPI, "_create_session")
    def test_execute_query(self, m_create_session, m_build_query, m_elastic_response):
        config = MagicMock()
        config_elastic = MagicMock()
        base_url = MagicMock()
        config_elastic.base_url = base_url
        config_elastic.api_key = None
        config_elastic.username = sentinel.username
        config_elastic.password = None
        config_elastic.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_elastic.offset = offset
        config_elastic.max_retry = sentinel.max_retry
        config_elastic.verify_ssl = sentinel.verify_ssl
        config_elastic.time_window = None
        config.elastic = config_elastic

        client_api = module.ElasticClientAPI(config)

        session = MagicMock()
        response = MagicMock()
        response.status_code = 200
        session.post.return_value = response
        client_api.session = session

        search_criteria = MagicMock()
        extend_end_seconds = MagicMock()

        alerts = client_api._execute_query(search_criteria, extend_end_seconds)

        m_build_query.assert_called_once_with(search_criteria, extend_end_seconds)
        session.post.assert_called_once_with(
            f"{base_url}/{sentinel.alerts_index}/_search",
            json=m_build_query.return_value,
            timeout=module.REQUEST_TIMEOUT_SECONDS,
        )
        m_elastic_response.from_raw_response.assert_called_with(
            response.json.return_value
        )
        self.assertEqual(
            alerts, m_elastic_response.from_raw_response.return_value.results
        )

    @patch.object(module, "ElasticResponse")
    @patch.object(module.ElasticClientAPI, "_build_query")
    @patch.object(module.ElasticClientAPI, "_create_session")
    def test_execute_query_authentication_error(
        self, m_create_session, m_build_query, m_elastic_response
    ):
        config = MagicMock()
        config_elastic = MagicMock()
        base_url = MagicMock()
        config_elastic.base_url = base_url
        config_elastic.api_key = None
        config_elastic.username = sentinel.username
        config_elastic.password = None
        config_elastic.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_elastic.offset = offset
        config_elastic.max_retry = sentinel.max_retry
        config_elastic.verify_ssl = sentinel.verify_ssl
        config_elastic.time_window = None
        config.elastic = config_elastic

        client_api = module.ElasticClientAPI(config)

        session = MagicMock()
        response = MagicMock()
        response.status_code = 401
        session.post.return_value = response
        client_api.session = session

        search_criteria = MagicMock()
        extend_end_seconds = MagicMock()

        with self.assertRaises(module.ElasticAuthenticationError):
            client_api._execute_query(search_criteria, extend_end_seconds)
            m_build_query.assert_called_once_with(search_criteria, extend_end_seconds)
            session.post.assert_called_once_with(
                f"{base_url}/{sentinel.alerts_index}/_search",
                json=m_build_query.return_value,
                timeout=module.REQUEST_TIMEOUT_SECONDS,
            )
        m_elastic_response.from_raw_response.assert_not_called()

    @patch.object(module.ElasticClientAPI, "_execute_query")
    @patch.object(module.time, "sleep")
    @patch.object(module.ElasticClientAPI, "_create_session")
    def test_execute_query_with_retry(self, m_create_session, m_sleep, m_execute_query):
        config = MagicMock()
        config_elastic = MagicMock()
        base_url = MagicMock()
        config_elastic.base_url = base_url
        config_elastic.api_key = None
        config_elastic.username = sentinel.username
        config_elastic.password = None
        config_elastic.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_elastic.offset = offset
        config_elastic.max_retry = 3
        config_elastic.verify_ssl = sentinel.verify_ssl
        config_elastic.time_window = None
        config.elastic = config_elastic

        client_api = module.ElasticClientAPI(config)

        search_criteria = MagicMock()
        _alerts = [MagicMock()]
        m_execute_query.return_value = _alerts

        alerts = client_api._execute_query_with_retry(search_criteria)

        m_sleep.assert_not_called()
        m_execute_query.assert_called_with(search_criteria, 0)
        self.assertEqual(alerts, _alerts)

    @patch.object(module.ElasticClientAPI, "_execute_query")
    @patch.object(module.time, "sleep")
    @patch.object(module.ElasticClientAPI, "_create_session")
    def test_execute_query_with_retry_authentication_error(
        self, m_create_session, m_sleep, m_execute_query
    ):
        config = MagicMock()
        config_elastic = MagicMock()
        base_url = MagicMock()
        config_elastic.base_url = base_url
        config_elastic.api_key = None
        config_elastic.username = sentinel.username
        config_elastic.password = None
        config_elastic.alerts_index = sentinel.alerts_index
        offset = MagicMock()
        config_elastic.offset = offset
        config_elastic.max_retry = 3
        config_elastic.verify_ssl = sentinel.verify_ssl
        config_elastic.time_window = None
        config.elastic = config_elastic

        client_api = module.ElasticClientAPI(config)

        search_criteria = MagicMock()
        m_execute_query.side_effect = module.ElasticAuthenticationError

        with self.assertRaises(module.ElasticAuthenticationError):
            client_api._execute_query_with_retry(search_criteria)
            m_sleep.assert_not_called()
            m_execute_query.assert_called_with(search_criteria, 0)
