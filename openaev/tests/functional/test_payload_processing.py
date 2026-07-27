import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, sentinel

import orjson

import openaev.openaev_openaev as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
    "openaev_url_prefix": "https://raw.githubusercontent.com/OpenAEV-Platform/payloads/refs/heads/main/",
    "collector_id": "collector-id",
}
json_flat_format_path = Path("./tests/functional/old_format.json")
json_api_format_path = Path("./tests/functional/new_format.json")


def fake_upsert_tag(data):
    return {"tag_id": f"id-{data.get('tag_name')}"}


class TestProcessingFunctions(unittest.TestCase):
    @patch.object(module, "GithubCrawler")
    def test_compare_process_results(self, m_github_crawler):
        _configuration = daemon_config_data
        api = MagicMock()
        api.tag.upsert.side_effect = fake_upsert_tag

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api

        json_flat_payload = orjson.loads(json_flat_format_path.read_bytes())
        self.assertTrue(collector._is_valid_json_flat(json_flat_payload))

        json_api_payload = orjson.loads(json_api_format_path.read_bytes())
        self.assertTrue(collector._is_valid_json_api(json_api_payload))

        json_flat_processor = module.JsonFlatProcessor(
            api=collector.api,
            logger=collector.api,
            payload_path=sentinel.json_flat_payload_path,
            github_crawler=collector.github_crawler,
        )
        json_flat_session = MagicMock()
        json_flat_processor.session = json_flat_session

        json_flat_payload_processed = json_flat_processor._process_payload(
            json_flat_payload
        )

        json_api_processor = module.JsonApiProcessor(
            api=collector.api,
            logger=collector.api,
            payload_path=sentinel.json_api_payload_path,
            github_crawler=collector.github_crawler,
        )
        json_api_session = MagicMock()
        json_api_processor.session = json_api_session

        json_api_payload_processed = json_api_processor._process_payload(
            json_api_payload
        )

        self.assertTrue(
            all(
                key in json_api_payload_processed
                for key in json_flat_payload_processed
                if json_flat_payload_processed[key]
            )
        )
        self.assertTrue(
            all(
                key in json_flat_payload_processed
                for key in json_api_payload_processed
                if json_api_payload_processed[key]
            )
        )

        self.assertTrue(
            all(
                type(json_flat_payload_processed[key])
                == type(json_api_payload_processed[key])
                for key in json_flat_payload_processed
                if json_flat_payload_processed[key]
            )
        )
        self.assertTrue(
            all(
                type(json_flat_payload_processed[key])
                == type(json_api_payload_processed[key])
                for key in json_api_payload_processed
                if json_api_payload_processed[key]
            )
        )

        exclusion_list = ["payload_created_at", "payload_updated_at"]
        for key in json_flat_payload_processed:
            if json_flat_payload_processed[key] and key not in exclusion_list:
                if isinstance(json_flat_payload_processed[key], dict):
                    self.assertEqual(
                        json_flat_payload_processed[key],
                        json_api_payload_processed[key],
                    )
                elif isinstance(json_flat_payload_processed[key], list):
                    try:
                        self.assertEqual(
                            sorted(json_flat_payload_processed[key]),
                            sorted(json_api_payload_processed[key]),
                        )
                    except TypeError:
                        self.assertTrue(
                            all(
                                element in json_api_payload_processed[key]
                                for element in json_flat_payload_processed[key]
                            )
                        )
                        self.assertTrue(
                            all(
                                element in json_flat_payload_processed[key]
                                for element in json_api_payload_processed[key]
                            )
                        )
                else:
                    self.assertEqual(
                        json_flat_payload_processed[key],
                        json_api_payload_processed[key],
                    )
        for key in json_api_payload_processed:
            if json_api_payload_processed[key] and key not in exclusion_list:
                if isinstance(json_api_payload_processed[key], dict):
                    self.assertEqual(
                        json_flat_payload_processed[key],
                        json_api_payload_processed[key],
                    )
                elif isinstance(json_api_payload_processed[key], list):
                    try:
                        self.assertEqual(
                            sorted(json_flat_payload_processed[key]),
                            sorted(json_api_payload_processed[key]),
                        )
                    except TypeError:
                        self.assertTrue(
                            all(
                                element in json_api_payload_processed[key]
                                for element in json_flat_payload_processed[key]
                            )
                        )
                        self.assertTrue(
                            all(
                                element in json_flat_payload_processed[key]
                                for element in json_api_payload_processed[key]
                            )
                        )
                else:
                    self.assertEqual(
                        json_flat_payload_processed[key],
                        json_api_payload_processed[key],
                    )
