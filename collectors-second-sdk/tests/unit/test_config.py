"""RED tests for config base classes."""

from __future__ import annotations

from datetime import timedelta

from collectors_second_sdk import (
    ConfigBaseSettings,
    ConfigLoaderCollector,
    ConfigLoaderCustom,
    ConfigLoaderOAEV,
)


class TestConfigBaseSettings:
    """ConfigBaseSettings is a BaseSettings subclass with frozen=True."""

    def test_is_base_settings(self) -> None:
        from pydantic_settings import BaseSettings

        assert issubclass(ConfigBaseSettings, BaseSettings)

    def test_frozen(self) -> None:
        assert ConfigBaseSettings.model_config.get("frozen") is True


class TestConfigLoaderOAEV:
    """OAEV config with url and token fields."""

    def test_has_url_field(self) -> None:
        assert "url" in ConfigLoaderOAEV.model_fields

    def test_has_token_field(self) -> None:
        assert "token" in ConfigLoaderOAEV.model_fields


class TestConfigLoaderCollector:
    """Collector config with id, name, platform, log_level, period, icon_filepath."""

    def test_has_id_field(self) -> None:
        assert "id" in ConfigLoaderCollector.model_fields

    def test_has_name_field(self) -> None:
        assert "name" in ConfigLoaderCollector.model_fields

    def test_has_platform_field(self) -> None:
        assert "platform" in ConfigLoaderCollector.model_fields

    def test_has_log_level_field(self) -> None:
        assert "log_level" in ConfigLoaderCollector.model_fields

    def test_has_period_field(self) -> None:
        assert "period" in ConfigLoaderCollector.model_fields

    def test_has_icon_filepath_field(self) -> None:
        assert "icon_filepath" in ConfigLoaderCollector.model_fields

    def test_platform_default(self) -> None:
        # Must accept construction with just id + name
        config = ConfigLoaderCollector(id="test-id", name="test")
        assert config.platform is not None


class TestConfigLoaderCustom:
    """Custom config with key, time_window, expectation_batch_size."""

    def test_has_key_field(self) -> None:
        assert "key" in ConfigLoaderCustom.model_fields

    def test_has_time_window_field(self) -> None:
        assert "time_window" in ConfigLoaderCustom.model_fields

    def test_has_expectation_batch_size_field(self) -> None:
        assert "expectation_batch_size" in ConfigLoaderCustom.model_fields

    def test_defaults(self) -> None:
        config = ConfigLoaderCustom()
        assert config.expectation_batch_size == 50
        assert isinstance(config.time_window, timedelta)
