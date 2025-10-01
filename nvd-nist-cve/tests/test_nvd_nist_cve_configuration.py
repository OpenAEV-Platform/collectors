from unittest import TestCase
from unittest.mock import patch

from nvd_nist_cve import NvdNistCveConfiguration


class NvdNistCveConfigurationTest(TestCase):

    @patch.dict(
        "os.environ",
        {
            "OPENAEV_URL": "http://localhost:8080",
            "OPENAEV_TOKEN": "super-token",
            "COLLECTOR_ID": "collector-42",
            "NVD_NIST_CVE_API_KEY": "nist-api-key",
        },
    )
    def test_configuration_loads_with_env_variables(self):
        config = NvdNistCveConfiguration()

        # Check a few known config keys
        assert config.get("openaev_url") == "http://localhost:8080"
        assert config.get("openaev_token") == "super-token"
        assert config.get("collector_id") == "collector-42"
        assert config.get("collector_name") == "NVD NIST CVE Collector"  # default
        assert config.get("collector_period") == 7200  # default
        assert (
            config.get("collector_icon_filepath") == "nvd_nist_cve/img/icon-nist.png"
        )  # default
        assert config.get("nvd_nist_cve_api_key") == "nist-api-key"
        assert (
            config.get("nvd_nist_cve_api_base_url")
            == "https://services.nvd.nist.gov/rest/json"
        )  # default
