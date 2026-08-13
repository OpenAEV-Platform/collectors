import os

from nvd_nist_cve.configuration.config_loader import ConfigLoader
from nvd_nist_cve.nvd_nist_cve_collector import NvdNistCveCollector


def main():
    if not os.environ.get("NVDNISTCVE_API_BASE_URL") and os.environ.get(
        "NVD_NIST_CVE_API_BASE_URL"
    ):
        os.environ["NVDNISTCVE_API_BASE_URL"] = os.environ.get(
            "NVD_NIST_CVE_API_BASE_URL"
        )
    if not os.environ.get("NVDNISTCVE_API_KEY") and os.environ.get(
        "NVD_NIST_CVE_API_KEY"
    ):
        os.environ["NVDNISTCVE_API_KEY"] = os.environ.get("NVD_NIST_CVE_API_KEY")
    if not os.environ.get("NVDNISTCVE_START_YEAR") and os.environ.get(
        "NVD_NIST_CVE_START_YEAR"
    ):
        os.environ["NVDNISTCVE_START_YEAR"] = os.environ.get("NVD_NIST_CVE_START_YEAR")

    NvdNistCveCollector(configuration=ConfigLoader().to_daemon_config()).start()
