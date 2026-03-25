import unittest
from datetime import datetime, timedelta
from unittest.mock import sentinel

import src.services.fetcher_logline as module


def test_fetchresult_minimal_init():
    """ testing the minimal init of the FetchResult object (only the required elements) """
    loglines = sentinel.loglines

    fetchresult = module.FetchResult(
        loglines=loglines,
    )

    assert fetchresult.loglines == sentinel.loglines

class LogLineFetcherTest(unittest.TestCase):
    def test_fetch_loglines_for_time_windows(self):
        """ test the fetch_loglines_for_time_windows function """
        fetcher = module.LogLineFetcher()
        start = datetime.now() - timedelta(100)
        end = datetime.now()

        result = fetcher.fetch_loglines_for_time_windows(start, end)

        assert isinstance(result, module.FetchResult)
        assert result.loglines == []

    def test_fetch_loglines_for_time_windows_validation_errors(self):
        """ test erronous parameters in fetch_loglines_for_time_windows """
        fetcher = module.LogLineFetcher()
        with self.assertRaises(module.HTTPLogwatcherValidationError):
            fetcher.fetch_loglines_for_time_windows("a", "b")

        end = datetime.now()
        start = datetime.now() + timedelta(100)
        with self.assertRaises(module.HTTPLogwatcherValidationError):
            fetcher.fetch_loglines_for_time_windows(start, end)
