from aws_resources.configuration.collector_config_override import \
    CollectorConfigOverride
from pydantic import Field
from pyoaev.configuration import (ConfigLoaderOAEV, Configuration,
                                  SettingsLoader)


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                # OpenAEV configuration (flattened)
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                # Collector configuration (flattened)
                "collector_id": {"data": self.collector.id},
                "collector_name": {"data": self.collector.name},
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                # Aws resources
                "aws_access_key_id": {"data": self.collector.aws_access_key_id},
                "aws_secret_access_key": {"data": self.collector.aws_secret_access_key},
                "aws_session_token": {"data": self.collector.aws_session_token},
                "aws_assume_role_arn": {"data": self.collector.aws_assume_role_arn},
                "aws_regions": {"data": self.collector.aws_regions},
            },
            config_base_model=self,
        )
