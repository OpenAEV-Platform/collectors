from unittest.mock import MagicMock, patch

import pytest
from src.collector.collector import Collector
from src.collector.exception import (
    CollectorConfigError,
    CollectorProcessingError,
    CollectorSetupError,
)


@pytest.fixture
def mock_daemon_init():
    with patch("pyoaev.daemons.CollectorDaemon.__init__", autospec=True) as mock_init:

        def set_logger(self, *args, **kwargs):
            self.logger = MagicMock()

        mock_init.side_effect = set_logger
        yield


def test_collector_init_error():
    with patch(
        "src.collector.collector.ConfigLoader", side_effect=Exception("config error")
    ):
        with pytest.raises(
            CollectorConfigError,
            match="Failed to initialize the collector: config error",
        ):
            # We don't use the mock_daemon_init fixture here to allow super().__init__ to be called (or attempted)
            Collector()


def test_collector_setup_error(mock_daemon_init):
    with patch("src.collector.collector.ConfigLoader") as mock_config_loader:
        mock_config = mock_config_loader.return_value
        mock_config.to_daemon_config.return_value = MagicMock()

        collector = Collector()
        # Ensure it has a logger before calling _setup
        collector.logger = MagicMock()
        collector.api = MagicMock()
        collector.get_id = MagicMock(return_value="test-id")

        # Mocking __init__ should have set logger if it wasn't mocked to do nothing
        # But we mocked it to return None.

        with patch(
            "pyoaev.daemons.CollectorDaemon._setup",
            side_effect=Exception("setup error"),
        ):
            with pytest.raises(
                CollectorSetupError, match="Failed to setup the collector: setup error"
            ):
                collector._setup()


def test_collector_process_callback_interrupt(mock_daemon_init):
    with patch("src.collector.collector.ConfigLoader") as mock_config_loader:
        mock_config = mock_config_loader.return_value
        mock_config.to_daemon_config.return_value = MagicMock()
        collector = Collector()
        collector.logger = MagicMock()
        collector.expectation_manager = MagicMock()
        collector.oaev_detection_helper = MagicMock()

        collector.expectation_manager.process_expectations.side_effect = (
            KeyboardInterrupt()
        )

        with patch("os._exit") as mock_exit:
            collector._process_callback()
            mock_exit.assert_called_once_with(0)


def test_collector_process_callback_error(mock_daemon_init):
    with patch("src.collector.collector.ConfigLoader") as mock_config_loader:
        mock_config = mock_config_loader.return_value
        mock_config.to_daemon_config.return_value = MagicMock()
        collector = Collector()
        collector.logger = MagicMock()
        collector.expectation_manager = MagicMock()
        collector.oaev_detection_helper = MagicMock()

        collector.expectation_manager.process_expectations.side_effect = Exception(
            "process error"
        )

        with pytest.raises(
            CollectorProcessingError, match="Processing error: process error"
        ):
            collector._process_callback()
