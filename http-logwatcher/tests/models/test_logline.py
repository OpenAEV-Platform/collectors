from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest.mock import sentinel

import src.models.logline as module


class LogLineTest(unittest.TestCase):
    def test_logline_minimal_init(self):
        """ testing the minimal init of the LogLine object (only the required elements) """
        datetimestamp = datetime.now(timezone.utc) - timedelta(250)
        filepath = Path("/foo/bar/access.log")
        ip_source = "1.2.3.4"
        request = "GET / HTTP/1.1"

        logline = module.LogLine(
            datetimestamp=datetimestamp,
            filepath=filepath,
            ip_source=ip_source,
            request=request,
        )

        self.assertIs(logline.datetimestamp, datetimestamp)
        self.assertIs(logline.filepath, filepath)
        self.assertIs(logline.ip_source, ip_source)
        self.assertIs(logline.request, request)

class AccessLogLineTest(unittest.TestCase):
    def test_accesslogline_minimal_init(self):
        """ testing the minimal init of the AccessLogLine object (only the required elements) """
        datetimestamp = datetime.now(timezone.utc) - timedelta(250)
        filepath = Path("/foo/bar/access.log")
        ip_source = "1.2.3.4"
        request = "GET / HTTP/1.1"

        logline = module.AccessLogLine(
            datetimestamp=datetimestamp,
            filepath=filepath,
            ip_source=ip_source,
            request=request,
        )

        self.assertIs(logline.datetimestamp, datetimestamp)
        self.assertIs(logline.filepath, filepath)
        self.assertIs(logline.ip_source, ip_source)
        self.assertIs(logline.request, request)
        self.assertTrue(isinstance(logline, module.LogLine))

class ErrorLogLineTest(unittest.TestCase):
    def test_logline_minimal_init(self):
        """ testing the minimal init of the ErrorLogLine object (only the required elements) """
        datetimestamp = datetime.now(timezone.utc) - timedelta(250)
        filepath = Path("/foo/bar/error.log")
        ip_source = "1.2.3.4"
        request = "GET /secrets HTTP/1.1"

        logline = module.ErrorLogLine(
            datetimestamp=datetimestamp,
            filepath=filepath,
            ip_source=ip_source,
            request=request,
        )

        self.assertIs(logline.datetimestamp, datetimestamp)
        self.assertIs(logline.filepath, filepath)
        self.assertIs(logline.ip_source, ip_source)
        self.assertIs(logline.request, request)
        self.assertTrue(isinstance(logline, module.LogLine))
