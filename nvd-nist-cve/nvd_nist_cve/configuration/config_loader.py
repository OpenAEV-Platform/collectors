from nvd_nist_cve.configuration.collector_config_override import CollectorConfigOverride
from nvd_nist_cve.configuration.nvd_nist_cve_config_override import (
    NvdNistCveConfigOverride,
)
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)
    nvdnistcve: NvdNistCveConfigOverride = Field(
        default_factory=NvdNistCveConfigOverride
    )

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
                # NVD NIST CVE
                "nvd_nist_cve_api_base_url": {"data": self.nvdnistcve.api_base_url},
                "nvd_nist_cve_api_key": {
                    "data": self.nvdnistcve.api_key.get_secret_value()
                },
                "nvd_nist_cve_start_year": {"data": self.nvdnistcve.start_year},
            },
            config_base_model=self,
        )
