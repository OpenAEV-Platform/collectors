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

class LogLineFetcherTest(unittest.TestCase):
    def test_logline_fetcher_init(self):
        """ testing the proper init of the LogLineFetcher object """
        logs_folder_path = Path("/foo/bar/")

        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        self.assertEqual(
            fetcher.access_log,
            logs_folder_path / "access.log",
        )
        self.assertEqual(
            fetcher.error_log,
            logs_folder_path / "error.log",
        )
        self.assertIsInstance(
            fetcher.access_timestamp_regex,
            re.Pattern,
        )
        self.assertIsInstance(
            fetcher.error_timestamp_regex,
            re.Pattern,
        )

    def test_check_valid_datetimes_valid(self):
        """ test valid parameters for check_valid_datetimes """
        logs_folder_path = Path("/foo/bar/")
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )
        start = datetime.now() - timedelta(100)
        end = datetime.now()

        fetcher.check_valid_datetimes(
            start_time=start,
            end_time=end,
        )

    def test_check_valid_datetimes_invalid_types(self):
        """ test erronous parameters (wrong types) for check_valid_datetimes """
        logs_folder_path = Path("/foo/bar/")
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

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
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )
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

    def test_check_logfiles_exist_valid(self):
        """ test check_logfiles_exist valid case """
        logs_folder_path = MagicMock()
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        fetcher.check_logfiles_exist()

        logs_folder_path.__truediv__.return_value.exists.assert_any_call()

    def test_check_logfiles_exist_missing_access(self):
        """ test check_logfiles_exist invalid case (missing access file) """
        logs_folder_path = MagicMock()
        logs_folder_path.__truediv__.return_value.exists.return_value = False
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        with self.assertRaises(module.HTTPLogwatcherFileError) as error:
            fetcher.check_logfiles_exist()

            logs_folder_path.__truediv__.return_value.exists.assert_called_once()
            self.assertEqual(
                error.exception.message,
                "missing acces.log file",
            )

    def test_check_logfiles_exist_missing_error(self):
        """ test check_logfiles_exist invalid case (missing error file) """
        logs_folder_path = MagicMock()
        logs_folder_path.__truediv__.return_value.exists.side_effect = [
            True, False
        ]
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        with self.assertRaises(module.HTTPLogwatcherFileError) as error:
            fetcher.check_logfiles_exist()

            self.assertEqual(
                error.exception.message,
                "missing error.log file",
            )

    @patch.object(module, "LogLine")
    @patch.object(module, "datetime")
    def test_parse_log(self, m_datetime, m_LogLine):
        """ testing the various calls made to inputs during the parse_log """
        start_time = datetime.now(timezone.utc) - timedelta(500)
        mid_time = datetime.now(timezone.utc) - timedelta(250)
        end_time = datetime.now(timezone.utc)
        logline = MagicMock()
        logpath = MagicMock()
        logpath.open.return_value = [logline]
        regex = MagicMock()
        pattern = MagicMock()
        source = "access"
        ip_regex = MagicMock()
        m_datetime.strptime.return_value = mid_time

        logs_folder_path = MagicMock()
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        results = fetcher.parse_log(
            start_time, end_time, logpath, regex, pattern, ip_regex, source
        )

        logpath.open.assert_called_once()
        regex.search.assert_called_with(logline)
        m_datetime.strptime.assert_called_with(
            regex.search.return_value.group.return_value,
            pattern,
        )
        ip_regex.search.assert_called_with(logline)
        m_LogLine.assert_called_with(
            ip_source=ANY,
            source="access",
        )
        self.assertEqual(
            results,
            [m_LogLine.return_value]
        )

    @patch.object(module.LogLineFetcher, "parse_log")
    def test_parse_access_log(self, m_parse_log):
        """ test the proper input mapping for parse_access_log """
        start_time = MagicMock()
        end_time = MagicMock()

        logs_folder_path = MagicMock()
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        fetcher.parse_access_log(
            start_time,
            end_time,
        )

        m_parse_log.assert_called_once_with(
            start_time,
            end_time,
            fetcher.access_log,
            fetcher.access_timestamp_regex,
            module.CLF_LOCAL_TIME_PATTERN,
            fetcher.access_ip_regex,
            "access",
        )

    @patch.object(module.LogLineFetcher, "parse_log")
    def test_parse_error_log(self, m_parse_log):
        """ test the proper input mapping for parse_error_log """
        start_time = MagicMock()
        end_time = MagicMock()

        logs_folder_path = MagicMock()
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        fetcher.parse_error_log(
            start_time,
            end_time,
        )

        m_parse_log.assert_called_once_with(
            start_time,
            end_time,
            fetcher.error_log,
            fetcher.error_timestamp_regex,
            module.DATETIME_STAMP_PATTERN,
            fetcher.error_ip_regex,
            "error",
        )

    @patch.object(module.LogLineFetcher, "parse_error_log")
    @patch.object(module.LogLineFetcher, "parse_access_log")
    @patch.object(module.LogLineFetcher, "check_logfiles_exist")
    @patch.object(module.LogLineFetcher, "check_valid_datetimes")
    def test_fetch_loglines_for_time_window(
        self,
        m_check_valid_datetimes,
        m_check_logfiles_exist,
        m_parse_access_log,
        m_parse_error_log,
    ):
        """ test the calls made by the fetch_loglines_for_time_window function """
        start_time = MagicMock()
        end_time = MagicMock()

        logs_folder_path = MagicMock()
        fetcher = module.LogLineFetcher(
            logs_folder_path=logs_folder_path
        )

        fetcher.fetch_loglines_for_time_window(
            start_time,
            end_time,
        )

        m_check_valid_datetimes.assert_called_with(start_time, end_time)
        m_check_logfiles_exist.assert_called_once()
        m_parse_access_log.assert_called_with(start_time, end_time)
        m_parse_error_log.assert_called_with(start_time, end_time)
