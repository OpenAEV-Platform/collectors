import unittest
from unittest.mock import MagicMock, patch, sentinel

import openaev.openaev_openaev as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
    "openaev_url_prefix": "https://raw.githubusercontent.com/OpenAEV-Platform/payloads/refs/heads/main/",
}


@patch.object(module, "GithubCrawler")
class TestOpenAEVOpenAEV(unittest.TestCase):
    def test_openaev_collector_init(self, m_githubcrawler):
        _configuration = daemon_config_data

        collector = module.OpenAEVOpenAEV(_configuration)

        self.assertEqual(
            collector.openaev_url_prefix, daemon_config_data["openaev_url_prefix"]
        )
        m_githubcrawler.assert_called_with("OpenAEV-Platform/payloads", "heads/main")
        self.assertEqual(collector.github_crawler, m_githubcrawler.return_value)

    def test_openaev_collector_is_valid_json_api(self, m_githubcrawler):
        _configuration = daemon_config_data

        collector = module.OpenAEVOpenAEV(_configuration)

        flag = collector._is_valid_json_api({"data": None})
        self.assertTrue(flag)
        flag = collector._is_valid_json_api({"payload_information": None})
        self.assertFalse(flag)

    def test_openaev_collector_is_valid_json_flat(self, m_githubcrawler):
        _configuration = daemon_config_data

        collector = module.OpenAEVOpenAEV(_configuration)

        flag = collector._is_valid_json_flat({"payload_information": None})
        self.assertTrue(flag)
        flag = collector._is_valid_json_flat({"data": None})
        self.assertFalse(flag)

    @patch.object(module, "JsonFlatProcessor")
    @patch.object(module, "JsonApiProcessor")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_flat")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_api")
    def test_openaev_collector_process_single_payload_jsonapi_case(
        self,
        m_is_valid_json_api,
        m_is_valid_json_flat,
        m_json_api_processor,
        m_json_flat_processor,
        m_githubcrawler,
    ):
        _configuration = daemon_config_data
        api = MagicMock()
        m_is_valid_json_api.return_value = True
        _payload = MagicMock()
        m_githubcrawler.return_value.get_json.return_value = _payload
        _output_payload = {"payload_name": "name", "payload_external_id": "external-id"}
        m_json_api_processor.return_value._process_payload.return_value = (
            _output_payload
        )

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        external_id = collector._process_single_payload(sentinel.payload_path)

        m_githubcrawler.return_value.get_json.assert_called_with(sentinel.payload_path)
        m_is_valid_json_api.assert_called_with(_payload)
        m_json_api_processor.assert_called_with(
            api=collector.api,
            logger=collector.logger,
            payload_path=sentinel.payload_path,
            github_crawler=collector.github_crawler,
        )
        m_json_api_processor.return_value._process_payload.assert_called_with(_payload)
        m_is_valid_json_flat.assert_not_called()
        m_json_flat_processor.assert_not_called()
        api.payload.upsert.assert_called_with(
            m_json_api_processor.return_value._process_payload.return_value
        )
        self.assertEqual(
            _output_payload["payload_collector"],
            collector._configuration.get("collector_id"),
        )
        self.assertEqual(external_id, "external-id")

    @patch.object(module, "JsonFlatProcessor")
    @patch.object(module, "JsonApiProcessor")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_flat")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_api")
    def test_openaev_collector_process_single_payload_jsonflat_case(
        self,
        m_is_valid_json_api,
        m_is_valid_json_flat,
        m_json_api_processor,
        m_json_flat_processor,
        m_githubcrawler,
    ):
        _configuration = daemon_config_data
        api = MagicMock()
        m_is_valid_json_api.return_value = False
        m_is_valid_json_flat.return_value = True
        _payload = MagicMock()
        m_githubcrawler.return_value.get_json.return_value = _payload
        _output_payload = {"payload_name": "name", "payload_external_id": "external-id"}
        m_json_flat_processor.return_value._process_payload.return_value = (
            _output_payload
        )

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        external_id = collector._process_single_payload(sentinel.payload_path)

        m_githubcrawler.return_value.get_json.assert_called_with(sentinel.payload_path)
        m_is_valid_json_api.assert_called_with(_payload)
        m_json_api_processor.assert_not_called()
        m_is_valid_json_flat.assert_called_with(_payload)
        m_json_flat_processor.assert_called_with(
            api=collector.api,
            logger=collector.logger,
            payload_path=sentinel.payload_path,
            github_crawler=collector.github_crawler,
        )
        m_json_flat_processor.return_value._process_payload.assert_called_with(_payload)
        api.payload.upsert.assert_called_with(
            m_json_flat_processor.return_value._process_payload.return_value
        )
        self.assertEqual(
            _output_payload["payload_collector"],
            collector._configuration.get("collector_id"),
        )
        self.assertEqual(external_id, "external-id")

    @patch.object(module.OpenAEVOpenAEV, "_process_single_payload")
    def test_openaev_collector_process_message(
        self, m_process_single_payload, m_githubcrawler
    ):
        _configuration = daemon_config_data
        payload_path = sentinel.payload_path
        m_githubcrawler.return_value.get_json_file_paths.return_value = [payload_path]
        api = MagicMock()

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        collector._process_message()

        m_githubcrawler.return_value.get_json_file_paths.assert_called_once()
        m_process_single_payload.assert_called_once()
        api.payload.deprecate.assert_called_with(
            {
                "collector_id": collector._configuration.get("collector_id"),
                "payload_external_ids": [m_process_single_payload.return_value],
            }
        )
