import unittest
from unittest.mock import MagicMock, patch, sentinel

import openaev.processors.common_processor as module


@patch.object(module, "requests")
class TestCommonProcessor(unittest.TestCase):
    def test_common_processor_init(self, m_requests):
        api = MagicMock()
        logger = MagicMock()
        payload_path = "test/payload.json"
        github_crawler = MagicMock()

        cprocessor = module.CommonProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler,
        )

        self.assertEqual(cprocessor.api, api)
        self.assertEqual(cprocessor.logger, logger)
        self.assertEqual(cprocessor.payload_path, payload_path)
        self.assertEqual(cprocessor.github_crawler, github_crawler)
        self.assertEqual(cprocessor.session, m_requests.Session.return_value)

    def test_common_processor_create_or_get_tag(self, m_requests):
        api = MagicMock()
        logger = MagicMock()
        payload_path = "test/payload.json"
        github_crawler = MagicMock()

        cprocessor = module.CommonProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler,
        )

        api.tag.upsert.return_value = {
            "tag_id": sentinel.tag_id,
        }
        tag_name = "my tag"

        tag_id = cprocessor._create_or_get_tag(tag_name)

        api.tag.upsert.assert_called_with(
            {"tag_name": tag_name, "tag_color": "#6b7280"}
        )
        self.assertEqual(tag_id, sentinel.tag_id)

        tag_color = "#123456"
        tag_id = cprocessor._create_or_get_tag(tag_name, tag_color)

        api.tag.upsert.assert_called_with(
            {"tag_name": tag_name, "tag_color": tag_color}
        )
        self.assertEqual(tag_id, sentinel.tag_id)

        api.tag.upsert.side_effect = Exception("failure")

        tag_id = cprocessor._create_or_get_tag(tag_name, tag_color)

        logger.warning.assert_called_with("Failed to upsert tag my tag: failure")
        self.assertIsNone(tag_id)

    @patch.object(module.CommonProcessor, "_create_or_get_tag")
    def test_common_processor_process_payload_tags(
        self, m_create_or_get_tag, m_requests
    ):
        api = MagicMock()
        logger = MagicMock()
        payload_path = "test/payload.json"
        github_crawler = MagicMock()

        cprocessor = module.CommonProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler,
        )

        api.tag.upsert.side_effect = [
            {"tag_id": "id_1"},
            {"tag_id": "id_2"},
        ]
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

        tags_mapping, new_tags = cprocessor._process_payload_tags(payload)

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

    def test_common_processor_process_payload_attack_patterns(self, m_requests):
        api = MagicMock()
        logger = MagicMock()
        payload_path = "test/payload.json"
        github_crawler = MagicMock()

        cprocessor = module.CommonProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler,
        )

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

        attack_patterns = cprocessor._process_payload_attack_patterns(payload)

        api.attack_pattern.upsert.assert_called_with(
            [{"attack_pattern_external_id": "foobar", "dead": "beef"}], True
        )
        self.assertEqual(attack_patterns, ["foobar"])

    @patch.object(module.mimetypes, "guess_type")
    @patch.object(module.zipfile, "ZipFile")
    @patch.object(module.io, "BytesIO")
    def test_openaev_collector_process_document(
        self, m_bytesio, m_zipfile, m_guess_type, m_requests
    ):
        api = MagicMock()
        logger = MagicMock()
        payload_path = "test/payload.json"
        github_crawler = MagicMock()

        cprocessor = module.CommonProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler,
        )

        session = MagicMock()
        cprocessor.session = session
        m_guess_type.return_value = "application/pdf", None

        document_key = "my document key"
        payload = {
            "my document key": {
                "id": "leftover-id",
                "type": "documents",
                "document_tags": [{"tag_id": "tag1"}],
                "document_target": "path.file",
                "document_path": "malware/malicious/evil/legit_document.docx",
            }
        }
        tags_mapping = {"tag1": {"key": "value"}}

        payload_document, new_document = cprocessor._process_document(
            payload, document_key, tags_mapping
        )

        self.assertIsNone(payload_document.get("id"))
        self.assertIsNone(payload_document.get("type"))
        self.assertEqual(payload_document["document_tags"], [{"key": "value"}])
        github_crawler.get_filepath_if_exists.assert_not_called()
        github_crawler.gen_raw_download_url.assert_called_with(
            "malware/malicious/evil/legit_document.docx"
        )
        session.get.assert_called_with(github_crawler.gen_raw_download_url.return_value)
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
        self.assertIsNotNone(new_document)
