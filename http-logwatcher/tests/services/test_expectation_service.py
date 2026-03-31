import unittest
from unittest.mock import MagicMock, sentinel

import src.services.expectation_service as module


class ExpectationServiceTest(unittest.TestCase):
    def test_init_failure_config_missing(self):
        """testing the init failure of ExpectationService due to missing conf"""
        with self.assertRaises(module.HTTPLogwatcherValidationError):
            module.ExpectationService(
                config=None,
            )

    def test_init_failure_logs_folder_path_missing(self):
        """testing the init failure of ExpectationService due to missing logs_folder_path value in conf"""
        subconfig_http_logwatcher = MagicMock(
            logs_folder_path=None,
        )
        config = MagicMock(
            http_logwatcher=subconfig_http_logwatcher,
        )

        with self.assertRaises(module.HTTPLogwatcherValidationError) as error:
            module.ExpectationService(
                config=config,
            )
            self.assertEqual(
                error.exception.message,
                "http_logwatcher.logs_folder_path cannot be None",
            )

    def test_expectationservice_minimal_init(self):
        """testing the proper init of the ExpectationService object"""
        subconfig_http_logwatcher = MagicMock(time_window=sentinel.time_window)
        config = MagicMock(
            http_logwatcher=subconfig_http_logwatcher,
        )

        expectation_service = module.ExpectationService(
            config=config,
        )

        assert expectation_service.time_window == sentinel.time_window
