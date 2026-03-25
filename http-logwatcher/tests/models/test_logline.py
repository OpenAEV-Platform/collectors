import unittest
from unittest.mock import sentinel

import src.models.logline as module


class LogLineTest(unittest.TestCase):
    def test_logline_minimal_init(self):
        """ testing the minimal init of the LogLine object (only the required elements) """
        raw = sentinel.raw

        module.LogLine(
            _raw=raw
        )

    def test_logline_private_attribute(self):
        """ testing the proper lack of access to the private attribute _raw """
        raw = sentinel.raw

        logline = module.LogLine(
            _raw=raw
        )

        with self.assertRaises(AttributeError):
            assert logline._raw == sentinel.raw
