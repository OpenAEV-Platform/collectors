from pathlib import Path
import unittest
from unittest.mock import sentinel

import src.models.logline as module


class LogLineTest(unittest.TestCase):
    def test_logline_minimal_init(self):
        """ testing the minimal init of the LogLine object (only the required elements) """
        ip_source = "1.2.3.4"
        source = "access"
        filepath = Path("/foo/bar/access.log")

        logline = module.LogLine(
            ip_source=ip_source,
            source=source,
            filepath=filepath,
        )

        self.assertIs(logline.ip_source, ip_source)
        self.assertIs(logline.source, source)
        self.assertIs(logline.filepath, filepath)
