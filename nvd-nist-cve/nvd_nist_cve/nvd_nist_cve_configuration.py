import os
from pathlib import Path

from pyoaev.configuration import Configuration


class NvdNistCveConfiguration(Configuration):
    def __init__(self):
        """
        Initialize NVD NIST CVE configuration.

        Raises:
            If configuration invalid
        """
        config_hints = self._get_nvd_nist_cve_config_hints()

        try:
            super().__init__(
                config_hints=config_hints,
                config_file_path=os.path.join(
                    Path(__file__).parent.resolve(), "config.yml"
                ),
            )
        except Exception as e:
            print(f"Collector failed to configure: {e}")
            raise

    @staticmethod
    def _get_nvd_nist_cve_config_hints() -> dict:
        """
        Get configuration hints for NVD NIST CVE collector.

        Returns:
            Dictionary of configuration hints
        """
        return {
            # OpenBAS configuration
            "openbas_url": {
                "env": "OPENBAS_URL",
                "file_path": ["openbas", "url"],
            },
            "openbas_token": {
                "env": "OPENBAS_TOKEN",
                "file_path": ["openbas", "token"],
            },
            # Collector configuration
            "collector_id": {
                "env": "COLLECTOR_ID",
                "file_path": ["collector", "id"],
            },
            "collector_name": {
                "env": "COLLECTOR_NAME",
                "file_path": ["collector", "name"],
                "default": "NVD NIST CVE Collector",
            },
            "collector_period": {
                "env": "COLLECTOR_PERIOD",
                "file_path": ["collector", "period"],
                "is_number": True,
                "default": 7200,
            },
            "collector_icon_filepath": {
                "env": "COLLECTOR_ICON_FILEPATH",
                "file_path": ["collector", "icon_filepath"],
                "default": "nvd_nist_cve/img/icon-nist.png",
            },
            "log_level": {
                "env": "COLLECTOR_LOG_LEVEL",
                "file_path": ["collector", "log_level"],
                "default": "warn",
            },
            # NVD NIST CVE API configuration
            "nvd_nist_cve_api_key": {
                "env": "NVD_NIST_CVE_API_KEY",
                "file_path": ["nvd_nist_cve", "api_key"],
            },
            "nvd_nist_cve_api_base_url": {
                "env": "NVD_NIST_CVE_API_BASE_URL",
                "file_path": ["nvd_nist_cve", "api_base_url"],
                "default": "https://services.nvd.nist.gov/rest/json",
            },
        }
