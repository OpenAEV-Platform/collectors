from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader
from xtm_one.configuration.collector_config_override import CollectorConfigOverride


def _optional_seconds(value: timedelta | None) -> int | None:
    """Convert an optional duration to whole seconds.

    Both period fields are typed ``timedelta | None``, so an explicit
    ``null`` in the YAML config must not crash the daemon-config build;
    ``None`` flows through and the runtime fallbacks apply (the daemon
    default for ``period``, one hour for ``import_period``).
    """
    return int(value.total_seconds()) if value is not None else None


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
                "collector_id": {"data": self.collector.id},
                "collector_name": {"data": self.collector.name},
                "collector_platform": {"data": self.collector.platform},
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": _optional_seconds(self.collector.period),
                    "is_number": True,
                },
                "import_period": {
                    "data": _optional_seconds(self.collector.import_period),
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                "xtm_one_url": {"data": self.collector.xtm_one_url},
                "xtm_one_token": {"data": self.collector.xtm_one_token},
                "validate_expectations": {"data": self.collector.validate_expectations},
                "include_bare_models": {"data": self.collector.include_bare_models},
                "agent_tags": {"data": self.collector.agent_tags},
            },
            config_base_model=self,
        )
