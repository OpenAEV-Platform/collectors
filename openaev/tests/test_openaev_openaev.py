import unittest
from unittest.mock import MagicMock, patch, sentinel

import openaev.openaev_openaev as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
    "openaev_url_prefix": "https://raw.githubusercontent.com/OpenAEV-Platform/payloads/refs/heads/main/",
}


class TestOpenAEVOpenAEV(unittest.TestCase):
    def test_openaev_collector_init(self):
        _configuration = daemon_config_data

        collector = module.OpenAEVOpenAEV(_configuration)

        self.assertIsInstance(collector.session, module.requests.Session)
        self.assertEqual(
            collector.openaev_url_prefix, daemon_config_data["openaev_url_prefix"]
        )

    def test_openaev_collector_create_or_get_tag(self):
        api = MagicMock()
        api.tag.upsert.return_value = {
            "tag_id": sentinel.tag_id,
        }
        tag_name = "my tag"
        _configuration = daemon_config_data

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        tag_id = collector._create_or_get_tag(tag_name)

        api.tag.upsert.assert_called_with(
            {"tag_name": tag_name, "tag_color": "#6b7280"}
        )
        self.assertEqual(tag_id, sentinel.tag_id)

        tag_color = "#123456"
        tag_id = collector._create_or_get_tag(tag_name, tag_color)

        api.tag.upsert.assert_called_with(
            {"tag_name": tag_name, "tag_color": tag_color}
        )
        self.assertEqual(tag_id, sentinel.tag_id)

        api.tag.upsert.side_effect = Exception("failure")
        logger = MagicMock()
        collector.logger = logger

        tag_id = collector._create_or_get_tag(tag_name, tag_color)

        logger.warning.assert_called_with("Failed to upsert tag my tag: failure")
        self.assertIsNone(tag_id)

    @patch.object(module.OpenAEVOpenAEV, "_create_or_get_tag")
    def test_openaev_collector_process_payload_tags(self, m_create_or_get_tag):
        _configuration = daemon_config_data
        api = MagicMock()
        api.tag.upsert.side_effect = [
            {"tag_id": "id_1"},
            {"tag_id": "id_2"},
        ]

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        m_create_or_get_tag.side_effect = [
            "id_3",
            "id_4",
        ]

        payload = {
            "native_collection": True,
            "payload_tags": [
                {
                    "tag_id": "1",
                    "tag_name": "first",
                    "tag_color": "#123456",
                    "foo": "bar",
                },
                {
                    "tag_id": "2",
                    "tag_name": "second",
                    "tag_color": "#098765",
                    "dead": "beef",
                },
            ],
        }

        tags_mapping, new_tags = collector._process_payload_tags(payload)

        api.tag.upsert.assert_any_call(
            {"tag_id": "1", "tag_name": "first", "tag_color": "#123456"},
        )
        api.tag.upsert.assert_called_with(
            {"tag_id": "2", "tag_name": "second", "tag_color": "#098765"},
        )
        m_create_or_get_tag.assert_any_call("source:openaev-datasets", "#ef4444")
        m_create_or_get_tag.assert_called_with("type:native", "#10b981")
        self.assertEqual(
            tags_mapping,
            {
                "1": "id_1",
                "2": "id_2",
            },
        )
        self.assertEqual(
            new_tags,
            [
                "id_1",
                "id_2",
                "id_3",
                "id_4",
            ],
        )

    def test_openaev_collector_process_payload_attack_patterns(self):
        _configuration = daemon_config_data
        api = MagicMock()

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        payload = {
            "payload_attack_patterns": [
                {
                    "attack_pattern_external_id": "foobar",
                    "dead": "beef",
                    "id": "1",
                    "type": "attack_pattern",
                }
            ]
        }

        attack_patterns = collector._process_payload_attack_patterns(payload)

        api.attack_pattern.upsert.assert_called_with(
            [{"attack_pattern_external_id": "foobar", "dead": "beef"}], True
        )
        self.assertEqual(attack_patterns, ["foobar"])

    @patch.object(module.zipfile, "ZipFile")
    @patch.object(module.io, "BytesIO")
    def test_openaev_collector_process_documents(self, m_bytesio, m_zipfile):
        _configuration = daemon_config_data
        api = MagicMock()
        session = MagicMock()

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api
        collector.session = session

        document_key = "my document key"
        payload = {
            "my document key": {
                "id": "leftover-id",
                "type": "documents",
                "document_tags": [{"tag_id": "tag1"}],
                "document_name": "path.file",
            }
        }
        tags_mapping = {"tag1": {"key": "value"}}

        payload_document, new_document = collector._process_document(
            payload, document_key, tags_mapping
        )

    def test_openaev_collector_is_valid_json_api(self):
        _configuration = daemon_config_data

        collector = module.OpenAEVOpenAEV(_configuration)

        flag = collector._is_valid_json_api({"data": None})
        self.assertTrue(flag)
        flag = collector._is_valid_json_api({"payload_information": None})
        self.assertFalse(flag)

    def test_openaev_collector_is_valid_json_flat(self):
        _configuration = daemon_config_data

        collector = module.OpenAEVOpenAEV(_configuration)

        flag = collector._is_valid_json_flat({"payload_information": None})
        self.assertTrue(flag)
        flag = collector._is_valid_json_flat({"data": None})
        self.assertFalse(flag)

    def test_openaev_collector_process_jsonapi_payload(self):
        pass

    def test_openaev_collector_process_jsonflat_payload(self):
        pass

    @patch.object(module.OpenAEVOpenAEV, "_process_jsonapi_payload")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_api")
    def test_openaev_collector_process_single_payload_jsonapi_case(
        self, m_is_valid_json_api, m_process_jsonapi_payload
    ):
        pass

    @patch.object(module.OpenAEVOpenAEV, "_process_jsonflat_payload")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_flat")
    def test_openaev_collector_process_single_payload_jsonflat_case(
        self, m_is_valid_json_flat, m_process_jsonflat_payload
    ):
        pass

    def test_openaev_collector_process_message(self):
        pass
