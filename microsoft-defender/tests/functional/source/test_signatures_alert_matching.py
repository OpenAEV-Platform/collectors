import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import orjson
import src.source.data_fetcher as data_fetcher_module
import src.source.source_handler as module
from pyoaev.apis.inject_expectation.model.expectation import Expectation
from pyoaev.client import OpenAEV
from src.collector.engines.basic import BasicCollectorEngine
from src.collector.models.source import Source
from src.source.signatures import SUPPORTED_SIGNATURES
from src.source.source_data import Alert

sample_one = Path("./tests/functional/source/alert_sample_one.json")
expectation_one = Path("./tests/functional/source/expectation_sample_one.json")


class TestDefenderSourceHandler(unittest.TestCase):
    @patch.object(data_fetcher_module, "MSGraphAuthClient")
    @patch.object(data_fetcher_module.DefenderDataFetcher, "fetch_data")
    def test_match_signature_groups_and_alert_data(
        self, m_fetch_data, m_ms_auth_client
    ):
        data_alert_one = orjson.loads(sample_one.read_bytes())
        object_alert_one = Alert(**data_alert_one)
        data_expectation_one = orjson.loads(expectation_one.read_bytes())
        object_expectation_one = Expectation(
            **data_expectation_one, api_client="api-client"
        )

        m_fetch_data.return_value = [object_alert_one]
        source = Source(
            data_fetcher_model=data_fetcher_module.DefenderDataFetcher,
            source_data_model=Alert,
            signatures=SUPPORTED_SIGNATURES,
        )
        oaev_api = MagicMock(spec_set=OpenAEV)
        source_config = MagicMock()
        source_handler = module.DefenderSourceHandler(source_config)

        engine = BasicCollectorEngine(
            name="name",
            collector_id="collector_id",
            source=source,
            source_handler=source_handler,
            oaev_api=oaev_api,
        )

        source_config = MagicMock()
        source_config.retry_window = timedelta(minutes=20)

        engine.configure_engine(source_config)

        batch = [object_expectation_one]

        result = engine._process_batch(batch)

        print(result)

        m_fetch_data.assert_called_once()
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].is_valid)
