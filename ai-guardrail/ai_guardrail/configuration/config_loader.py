from ai_guardrail.configuration.collector_config_override import CollectorConfigOverride
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                # OpenAEV configuration (flattened)
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
                # Collector configuration (flattened)
                "collector_id": {"data": self.collector.id},
                "collector_name": {"data": self.collector.name},
                "collector_platform": {"data": self.collector.platform},
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                # Guardrail backend (flattened)
                "guardrail_provider": {"data": self.collector.provider},
                "guardrail_events_url": {"data": self.collector.events_url},
                "guardrail_api_key": {"data": self.collector.api_key},
                "guardrail_lookback_minutes": {
                    "data": self.collector.lookback_minutes,
                    "is_number": True,
                },
                "guardrail_marker_param": {"data": self.collector.marker_param},
                "guardrail_flagged_field": {"data": self.collector.flagged_field},
                "guardrail_blocked_field": {"data": self.collector.blocked_field},
            },
            config_base_model=self,
        )
