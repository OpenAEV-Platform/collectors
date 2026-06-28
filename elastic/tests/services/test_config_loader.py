"""Tests for the Elastic Security configuration loader logging.

The ``services`` conftest auto-mocks ``logging.getLogger`` (see the
``mock_logging`` autouse fixture), so these tests inspect the recorded calls on
that shared mock logger rather than using ``caplog``.
"""

from unittest.mock import MagicMock, patch

from src.services.utils.config_loader import ElasticConfig


def _build_settings(base_url: str) -> MagicMock:
    """Build a mock settings object with the attributes the loader logs."""
    settings = MagicMock()
    settings.collector.id = "elastic--0b13e3f7"
    settings.collector.name = "Elastic"
    settings.collector.log_level = "info"
    settings.openaev.url = "https://openaev.example.com"
    settings.elastic.base_url = base_url
    return settings


def _logged_text(mock_get_logger: MagicMock) -> str:
    """Join every message passed to the shared mock logger."""
    logger = mock_get_logger.return_value
    calls = (
        logger.debug.call_args_list
        + logger.info.call_args_list
        + logger.warning.call_args_list
        + logger.error.call_args_list
    )
    return " ".join(str(call.args[0]) for call in calls if call.args)


def test_load_config_redacts_base_url_credentials(mock_logging):
    """The debug log of base_url must never expose ``user:pass@`` credentials."""
    settings = _build_settings("https://elastic:s3cr3t@es.example.com:9200")

    with patch("src.services.utils.config_loader.ConfigLoader", return_value=settings):
        ElasticConfig()

    logged = _logged_text(mock_logging)

    assert "s3cr3t" not in logged  # noqa: S101
    assert "elastic:s3cr3t@" not in logged  # noqa: S101
    assert "es.example.com:9200" in logged  # noqa: S101


def test_load_config_logs_plain_base_url_unchanged(mock_logging):
    """A base_url without credentials is logged as-is."""
    settings = _build_settings("https://es.example.com:9200")

    with patch("src.services.utils.config_loader.ConfigLoader", return_value=settings):
        ElasticConfig()

    logged = _logged_text(mock_logging)

    assert "https://es.example.com:9200" in logged  # noqa: S101
