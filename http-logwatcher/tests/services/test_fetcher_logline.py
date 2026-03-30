from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import unittest
from unittest.mock import ANY, MagicMock, patch, sentinel

import src.services.fetcher_logline as module


def test_fetchresult_minimal_init():
    """ testing the minimal init of the FetchResult object (only the required elements) """
    loglines = sentinel.loglines

    fetchresult = module.FetchResult(
        loglines=loglines,
    )

    assert fetchresult.loglines == sentinel.loglines

class LineFetcherTest(unittest.TestCase):
    def test_check_valid_datetimes_valid(self):
        """ test valid parameters for check_valid_datetimes """
        logs_folder_path = Path("/foo/bar/")
        fetcher = module.LogLineFetcher()
        start = datetime.now() - timedelta(100)
        end = datetime.now()

        fetcher.check_valid_datetimes(
            start_time=start,
            end_time=end,
        )

    def test_check_valid_datetimes_invalid_types(self):
        """ test erronous parameters (wrong types) for check_valid_datetimes """
        logs_folder_path = Path("/foo/bar/")
        fetcher = module.LogLineFetcher()

        with self.assertRaises(module.HTTPLogwatcherValidationError) as error:
            fetcher.check_valid_datetimes(
                start_time="a",
                end_time="b",
            )

            self.assertEqual(
                error.exception.message,
                "start_time and end_time must be datetime objects",
            )

    def test_check_valid_datetimes_invalid_times(self):
        """ test erronous parameters (wrong values) for check_valid_datetimes """
        logs_folder_path = Path("/foo/bar/")
        fetcher = module.LogLineFetcher()
        start = datetime.now() + timedelta(500)
        end = datetime.now()

        with self.assertRaises(module.HTTPLogwatcherValidationError) as error:
            fetcher.check_valid_datetimes(
                start_time=start,
                end_time=end,
            )

            self.assertEqual(
                error.exception.message,
                "start_time must be before end_time",
            )

    def test_check_logfile_exists_valid(self):
        """ test check_logfile_exists valid case """
        fetcher = module.LogLineFetcher()
        logpath = MagicMock()
        fetcher.logpath = logpath

        fetcher.check_logfile_exists()

        logpath.exists.assert_any_call()

    def test_check_logfile_exists_missing_access(self):
        """ test check_logfile_exists invalid case (missing access file) """
        fetcher = module.LogLineFetcher()
        logpath = MagicMock()
        logpath.exists.return_value = False
        fetcher.logpath = logpath

        with self.assertRaises(module.HTTPLogwatcherFileError) as error:
            fetcher.check_logfile_exists()

            logpath.exists.assert_called_once()
            self.assertEqual(
                error.exception.message,
                "missing acces.log file",
            )

    @patch.object(module, "datetime")
    def test_parse_log(self, m_datetime):
        """ testing the various calls made to inputs during the parse_log """
        start_time = datetime.now(timezone.utc) - timedelta(500)
        mid_time = datetime.now(timezone.utc) - timedelta(250)
        end_time = datetime.now(timezone.utc)
        m_datetime.strptime.return_value = mid_time

        fetcher = module.LogLineFetcher()
        logpath = MagicMock()
        logline = MagicMock()
        logpath.open.return_value = [logline]
        fetcher.logpath = logpath
        timestamp_regex = MagicMock()
        fetcher.timestamp_regex = timestamp_regex
        strptime_pattern = MagicMock()
        fetcher.strptime_pattern = strptime_pattern
        ip_regex = MagicMock()
        fetcher.ip_regex = ip_regex
        request_regex = MagicMock()
        fetcher.request_regex = request_regex
        logline_type = MagicMock()
        fetcher.logline_type = logline_type

        results = fetcher.parse_log(
            start_time, end_time,
        )

        logpath.open.assert_called_once()
        timestamp_regex.search.assert_called_with(logline)
        m_datetime.strptime.assert_called_with(
            timestamp_regex.search.return_value.group.return_value,
            strptime_pattern,
        )
        ip_regex.search.assert_called_with(logline)
        logline_type.assert_called_with(
            datetimestamp=mid_time,
            filepath=logpath,
            ip_source=ip_regex.search.return_value.group.return_value,
            request=request_regex.search.return_value.group.return_value,
        )
        self.assertEqual(
            results,
            [logline_type.return_value]
        )

    @patch.object(module.LogLineFetcher, "parse_log")
    @patch.object(module.LogLineFetcher, "check_logfile_exists")
    @patch.object(module.LogLineFetcher, "check_valid_datetimes")
    def test_fetch_loglines_for_time_window(
        self,
        m_check_valid_datetimes,
        m_check_logfile_exists,
        m_parse_log,
    ):
        """ test the calls made by the fetch_loglines_for_time_window function """
        start_time = MagicMock()
        end_time = MagicMock()

        fetcher = module.LogLineFetcher()
        logpath = MagicMock()
        fetcher.logpath = logpath

        fetcher.fetch_loglines_for_time_window(
            start_time,
            end_time,
        )

        m_check_valid_datetimes.assert_called_with(start_time, end_time)
        m_check_logfile_exists.assert_called_once()
        m_parse_log.assert_called_with(start_time, end_time)

class AccessLogLineFetcherTest(unittest.TestCase):
    def test_access_logline_fetcher_init(self):
        """ testing the proper init of the AccessLogLineFetcher object """
        logs_folder_path = Path("/foo/bar/")

        fetcher = module.AccessLogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        self.assertEqual(
            fetcher.logline_type,
            module.AccessLogLine,
        )
        self.assertEqual(
            fetcher.logpath,
            logs_folder_path / "access.log",
        )
        self.assertIsInstance(
            fetcher.timestamp_regex,
            re.Pattern,
        )
        self.assertIsInstance(
            fetcher.ip_regex,
            re.Pattern,
        )
        self.assertIsInstance(
            fetcher.request_regex,
            re.Pattern,
        )

class ErrorLogLineFetcherTest(unittest.TestCase):
    def test_error_logline_fetcher_init(self):
        """ testing the proper init of the ErrorLogLineFetcher object """
        logs_folder_path = Path("/foo/bar/")

        fetcher = module.ErrorLogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        self.assertEqual(
            fetcher.logline_type,
            module.ErrorLogLine,
        )
        self.assertEqual(
            fetcher.logpath,
            logs_folder_path / "error.log",
        )
        self.assertIsInstance(
            fetcher.timestamp_regex,
            re.Pattern,
        )
        self.assertIsInstance(
            fetcher.ip_regex,
            re.Pattern,
        )
        self.assertIsInstance(
            fetcher.request_regex,
            re.Pattern,
        )
