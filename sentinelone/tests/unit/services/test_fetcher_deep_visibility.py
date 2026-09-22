import unittest
from unittest.mock import ANY, MagicMock, patch, sentinel

import src.services.fetcher_deep_visibility as module


class TestFetcherDeepVisibility(unittest.TestCase):
    def test_init(self):
        client_api = MagicMock()

        fetcher = module.FetcherDeepVisibility(client_api)

        self.assertEqual(fetcher.client_api, client_api)

    @patch.object(module.FetcherDeepVisibility, "_execute_query")
    @patch.object(module.FetcherDeepVisibility, "_init_dv_query")
    def test_fetch_events_for_sha1(self, m_init_dv_query, m_execute_query):
        client_api = MagicMock()
        fetcher = module.FetcherDeepVisibility(client_api)

        sha1 = "sha-one"
        start_time = sentinel.start_time
        end_time = sentinel.end_time
        all_events = [
            {"fileSha1": "sha-one"},
            {"fileSha1": "sha-two"},
        ]
        m_execute_query.return_value = all_events

        events = fetcher.fetch_events_for_sha1(sha1, start_time, end_time)

        m_init_dv_query.assert_called_with([sha1], sentinel.start_time, sentinel.end_time)
        m_execute_query.assert_called_with(m_init_dv_query.return_value)
        self.assertEqual(events, [{"fileSha1": "sha-one"}])

    @patch.object(module.FetcherDeepVisibility, "_parse_error_response")
    @patch.object(module.FetcherDeepVisibility, "_calculate_wait_time")
    def test_wait_for_query_completion(self, m_calculate_wait_time, m_parse_error_response):
        client_api = MagicMock()
        client_api.base_url = "http://base.url"
        response = MagicMock()
        response.status_code = 200
        data = {
            "progressStatus": 50,
            "responseState": "FINISHED",
        }
        response.json.return_value = {"data": data}
        client_api.session.get.return_value = response
        fetcher = module.FetcherDeepVisibility(client_api)

        query_id = sentinel.query_id
        fetcher._wait_for_query_completion(query_id)

        client_api.session.get.assert_called_with(
            "http://base.url/web/api/v2.1/dv/query-status",
            params={"queryId": sentinel.query_id},
            timeout=module.REQUEST_TIMEOUT_SECONDS,
        )
        m_calculate_wait_time.assert_not_called()
        m_parse_error_response.assert_not_called()

    @patch.object(module.time, "sleep")
    @patch.object(module.FetcherDeepVisibility, "_parse_error_response")
    @patch.object(module.FetcherDeepVisibility, "_calculate_wait_time")
    def test_wait_for_query_completion_two_loops(self, m_calculate_wait_time, m_parse_error_response, m_sleep):
        client_api = MagicMock()
        client_api.base_url = "http://base.url"
        response1 = MagicMock()
        response1.status_code = 200
        data1 = {
            "progressStatus": 50,
            "responseState": "",
        }
        response1.json.return_value = {"data": data1}
        response2 = MagicMock()
        response2.status_code = 200
        data2 = {
            "progressStatus": 60,
            "responseState": "FINISHED",
        }
        response2.json.return_value = {"data": data2}
        client_api.session.get.side_effect = [response1, response2]
        fetcher = module.FetcherDeepVisibility(client_api)

        query_id = sentinel.query_id
        fetcher._wait_for_query_completion(query_id)

        client_api.session.get.assert_called_with(
            "http://base.url/web/api/v2.1/dv/query-status",
            params={"queryId": sentinel.query_id},
            timeout=module.REQUEST_TIMEOUT_SECONDS,
        )
        m_calculate_wait_time.assert_called_with(50, 0)
        m_sleep.assert_called_with(m_calculate_wait_time.return_value)
        m_parse_error_response.assert_not_called()

    @patch.object(module.FetcherDeepVisibility, "_parse_error_response")
    @patch.object(module.FetcherDeepVisibility, "_calculate_wait_time")
    def test_wait_for_query_completion_raise_http500(self, m_calculate_wait_time, m_parse_error_response):
        client_api = MagicMock()
        client_api.base_url = "http://base.url"
        response = MagicMock()
        response.status_code = 500
        client_api.session.get.return_value = response
        fetcher = module.FetcherDeepVisibility(client_api)

        query_id = sentinel.query_id

        with self.assertRaises(module.SentinelOneAPIError):
            fetcher._wait_for_query_completion(query_id)

            client_api.session.get.assert_called_with(
                "http://base.url/web/api/v2.1/dv/query-status",
                params={"queryId": sentinel.query_id},
                timeout=module.REQUEST_TIMEOUT_SECONDS,
            )
            m_calculate_wait_time.assert_not_called()
            m_parse_error_response.assert_called_with(response)

    @patch.object(module.FetcherDeepVisibility, "_parse_error_response")
    def test_make_real_events_query(self, m_parse_error_response):
        client_api = MagicMock()
        client_api.base_url = "http://base.url"
        response = MagicMock()
        response.status_code = 200
        data = MagicMock()
        response.json.return_value = {"data": data}
        client_api.session.get.return_value = response
        fetcher = module.FetcherDeepVisibility(client_api)

        query_id = sentinel.query_id
        events = fetcher._make_real_events_query(query_id)

        client_api.session.get.assert_called_with(
            "http://base.url/web/api/v2.1/dv/events",
            params={"queryId": sentinel.query_id},
            timeout=module.REQUEST_TIMEOUT_SECONDS,
        )
        self.assertEqual(events, data)
        m_parse_error_response.assert_not_called()

    @patch.object(module.FetcherDeepVisibility, "_parse_error_response")
    def test_make_real_events_query_http500(self, m_parse_error_response):
        client_api = MagicMock()
        client_api.base_url = "http://base.url"
        response = MagicMock()
        response.status_code = 500
        client_api.session.get.return_value = response
        fetcher = module.FetcherDeepVisibility(client_api)

        query_id = sentinel.query_id

        with self.assertRaises(module.SentinelOneAPIError):
            fetcher._make_real_events_query(query_id)
            client_api.session.get.assert_called_with(
                "http://base.url/web/api/v2.1/dv/events",
                params={"queryId": sentinel.query_id},
                timeout=module.REQUEST_TIMEOUT_SECONDS,
            )
            m_parse_error_response.assert_called_with(response)

    def test_format_timestamp_for_api(self):
        client_api = MagicMock()
        fetcher = module.FetcherDeepVisibility(client_api)

        dt = MagicMock()
        dt.tzinfo = None

        formatted_dt = fetcher._format_timestamp_for_api(dt)

        dt.replace.assert_called_with(tzinfo=module.timezone.utc)
        self.assertEqual(formatted_dt, dt.replace.return_value.replace.return_value.isoformat.return_value+"Z")

        dt = MagicMock()
        dt.tzinfo = "not-UTC"

        formatted_dt = fetcher._format_timestamp_for_api(dt)

        dt.astimezone.assert_called_with(module.timezone.utc)
        self.assertEqual(formatted_dt, dt.astimezone.return_value.replace.return_value.isoformat.return_value+"Z")

        dt = MagicMock()
        dt.tzinfo = module.timezone.utc

        formatted_dt = fetcher._format_timestamp_for_api(dt)

        self.assertEqual(formatted_dt, dt.replace.return_value.isoformat.return_value+"Z")
