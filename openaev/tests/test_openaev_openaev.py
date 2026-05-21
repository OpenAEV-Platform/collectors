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

        self.assertIsInstance(collector.session, module.requests.Session)
        self.assertEqual(
            collector.openaev_url_prefix, daemon_config_data["openaev_url_prefix"]
        )
        m_githubcrawler.assert_called_with("OpenAEV-Platform/payloads", "heads/main")
        self.assertEqual(collector.github_crawler, m_githubcrawler.return_value)
        self.assertIsNone(collector.current_payload_path)

    def test_openaev_collector_create_or_get_tag(self, m_githubcrawler):
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
    def test_openaev_collector_process_payload_tags(
        self, m_create_or_get_tag, m_githubcrawler
    ):
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

    def test_openaev_collector_process_payload_attack_patterns(self, m_githubcrawler):
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

    @patch.object(module.mimetypes, "guess_type")
    @patch.object(module.zipfile, "ZipFile")
    @patch.object(module.io, "BytesIO")
    def test_openaev_collector_process_document(
        self, m_bytesio, m_zipfile, m_guess_type, m_githubcrawler
    ):
        _configuration = daemon_config_data
        api = MagicMock()
        session = MagicMock()
        m_guess_type.return_value = "application/pdf", None

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
                "document_path": "malware/malicious/evil/legit_document.docx",
            }
        }
        tags_mapping = {"tag1": {"key": "value"}}

        payload_document, new_document = collector._process_document(
            payload, document_key, tags_mapping
        )

        self.assertIsNone(payload_document.get("id"))
        self.assertIsNone(payload_document.get("type"))
        self.assertEqual(payload_document["document_tags"], [{"key": "value"}])
        m_githubcrawler.return_value.get_filepath_if_exists.assert_not_called()
        m_githubcrawler.return_value.gen_raw_download_url.assert_called_with(
            "malware/malicious/evil/legit_document.docx"
        )
        session.get.assert_called_with(
            m_githubcrawler.return_value.gen_raw_download_url.return_value
        )
        session.get.return_value.raise_for_status.assert_called_once()
        m_bytesio.assert_any_call(session.get.return_value.content)
        m_guess_type.assert_called_with("path.file")
        api.document.upsert.assert_called_with(
            document=payload_document,
            file=(
                "path.file",
                m_bytesio.return_value.__enter__.return_value,
                "application/pdf",
            ),
        )

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

    @patch.object(module.OpenAEVOpenAEV, "_process_document")
    @patch.object(module.OpenAEVOpenAEV, "_process_payload_attack_patterns")
    @patch.object(module.OpenAEVOpenAEV, "_process_payload_tags")
    @patch.object(module, "json_api_doc")
    def test_openaev_collector_process_jsonapi_payload(
        self,
        m_json_api_doc,
        m_process_payload_tags,
        m_process_payload_attack_patterns,
        m_process_document,
        m_githubcrawler,
    ):
        _configuration = daemon_config_data
        api = MagicMock()
        payload = MagicMock()
        flat_payload = {
            "id": "json api id",
            "type": "payloads",
            "payload_id": "payload id",
            "payload_name": "payload name",
            "dropper": {"type": "documents"},
            "payload_domains": [
                {
                    "domain_name": "domain name",
                    "domain_color": "domain color",
                    "type": "domains",
                    "id": "domain id",
                }
            ],
        }
        m_json_api_doc.deserialize.return_value = flat_payload
        tags_mapping = MagicMock()
        new_tags = MagicMock()
        m_process_payload_tags.return_value = tags_mapping, new_tags
        payload_document = MagicMock()
        new_document = MagicMock()
        m_process_document.return_value = payload_document, new_document

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        external_id = collector._process_jsonapi_payload(payload)

        m_json_api_doc.deserialize.assert_called_with(payload)
        m_process_payload_tags.assert_called_with(flat_payload)
        self.assertEqual(flat_payload["payload_tags"], new_tags)
        m_process_payload_attack_patterns.assert_called_with(flat_payload)
        self.assertEqual(
            flat_payload["payload_attack_patterns"],
            m_process_payload_attack_patterns.return_value,
        )
        m_process_document.assert_called_with(flat_payload, "dropper", tags_mapping)
        self.assertIsNone(flat_payload.get("dropper"))
        self.assertEqual(flat_payload["payload_document"], payload_document)
        self.assertEqual(
            flat_payload["payload_domains"],
            [{"domain_name": "domain name", "domain_color": "domain color"}],
        )
        self.assertIsNone(flat_payload.get("id"))
        self.assertIsNone(flat_payload.get("type"))
        self.assertIsNone(flat_payload.get("payload_id"))
        self.assertEqual(
            flat_payload["payload_collector"],
            collector._configuration.get("collector_id"),
        )
        api.payload.upsert.assert_called_with(flat_payload)
        self.assertEqual(external_id, "payload id")

    @patch.object(module.OpenAEVOpenAEV, "_process_document")
    @patch.object(module.OpenAEVOpenAEV, "_process_payload_attack_patterns")
    @patch.object(module.OpenAEVOpenAEV, "_process_payload_tags")
    def test_openaev_collector_process_jsonflat_payload(
        self,
        m_process_payload_tags,
        m_process_payload_attack_patterns,
        m_process_document,
        m_githubcrawler,
    ):
        payload_information = {
            "payload_external_id": "payload external id",
            "payload_name": "payload name",
        }
        payload = {
            "payload_information": payload_information,
        }
        _configuration = daemon_config_data
        api = MagicMock()
        tags_mapping = MagicMock()
        new_tags = MagicMock()
        m_process_payload_tags.return_value = tags_mapping, new_tags
        payload_document = MagicMock()
        new_document = MagicMock()
        m_process_document.return_value = payload_document, new_document

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        external_id = collector._process_jsonflat_payload(payload)

        m_process_payload_tags.assert_called_with(payload)
        self.assertEqual(payload_information["payload_tags"], new_tags)
        m_process_payload_attack_patterns.assert_called_with(payload)
        self.assertEqual(
            payload_information["payload_attack_patterns"],
            m_process_payload_attack_patterns.return_value,
        )
        m_process_document.assert_called_with(payload, "payload_document", tags_mapping)
        self.assertEqual(
            payload_information["payload_collector"],
            collector._configuration.get("collector_id"),
        )
        api.payload.upsert.assert_called_with(payload_information)
        self.assertEqual(external_id, "payload external id")

    @patch.object(module.OpenAEVOpenAEV, "_process_jsonflat_payload")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_flat")
    @patch.object(module.OpenAEVOpenAEV, "_process_jsonapi_payload")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_api")
    def test_openaev_collector_process_single_payload_jsonapi_case(
        self,
        m_is_valid_json_api,
        m_process_jsonapi_payload,
        m_is_valid_json_flat,
        m_process_jsonflat_payload,
        m_githubcrawler,
    ):
        _configuration = daemon_config_data
        m_is_valid_json_api.return_value = True

        collector = module.OpenAEVOpenAEV(_configuration)

        collector.current_payload_path = sentinel.payload_path
        _payload = MagicMock
        m_githubcrawler.return_value.get_json.return_value = _payload

        data = collector._process_single_payload()

        m_githubcrawler.return_value.get_json.assert_called_with(sentinel.payload_path)
        m_is_valid_json_api.assert_called_with(_payload)
        m_process_jsonapi_payload.assert_called_with(_payload)
        m_is_valid_json_flat.assert_not_called()
        m_process_jsonflat_payload.assert_not_called()
        self.assertEqual(data, m_process_jsonapi_payload.return_value)

    @patch.object(module.OpenAEVOpenAEV, "_process_jsonflat_payload")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_flat")
    @patch.object(module.OpenAEVOpenAEV, "_process_jsonapi_payload")
    @patch.object(module.OpenAEVOpenAEV, "_is_valid_json_api")
    def test_openaev_collector_process_single_payload_jsonflat_case(
        self,
        m_is_valid_json_api,
        m_process_jsonapi_payload,
        m_is_valid_json_flat,
        m_process_jsonflat_payload,
        m_githubcrawler,
    ):
        _configuration = daemon_config_data
        m_is_valid_json_api.return_value = False
        m_is_valid_json_flat.return_value = True

        collector = module.OpenAEVOpenAEV(_configuration)

        collector.current_payload_path = sentinel.payload_path
        _payload = MagicMock
        m_githubcrawler.return_value.get_json.return_value = _payload

        data = collector._process_single_payload()

        m_githubcrawler.return_value.get_json.assert_called_with(sentinel.payload_path)
        m_is_valid_json_api.assert_called_with(_payload)
        m_process_jsonapi_payload.assert_not_called()
        m_is_valid_json_flat.assert_called_with(_payload)
        m_process_jsonflat_payload.assert_called_with(_payload)
        self.assertEqual(data, m_process_jsonflat_payload.return_value)

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
        self.assertEqual(collector.current_payload_path, sentinel.payload_path)
        api.payload.deprecate.assert_called_with(
            {
                "collector_id": collector._configuration.get("collector_id"),
                "payload_external_ids": [m_process_single_payload.return_value],
            }
        )
