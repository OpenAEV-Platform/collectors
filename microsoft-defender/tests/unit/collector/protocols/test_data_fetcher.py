import unittest
from unittest.mock import MagicMock

import src.collector.protocols.data_fetcher as module


class DataFetcherProtocolTest(unittest.TestCase):
    def test_following_data_fetcher_protocol(self):
        """verify that a class following the protocol is seen as such"""

        class GoodDataFetcher:
            def fetch_data(self):
                return [MagicMock()]

        self.assertTrue(issubclass(GoodDataFetcher, module.DataFetcherProtocol))

    def test_not_following_data_fetcher_protocol(self):
        """verify that a class not following the protocol is detected as such"""

        class BadDataFetcher:
            def retrieve_data(self):
                return [MagicMock()]

        self.assertFalse(issubclass(BadDataFetcher, module.DataFetcherProtocol))
