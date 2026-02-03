import os

from nvd_nist_cve.configuration.config_loader import ConfigLoader
from nvd_nist_cve.nvd_nist_cve_collector import NvdNistCveCollector


def main():
    """
    Main entry point for the NVD NIST CVE collector.

    Creates and starts the collector daemon with default configuration.
    Designed to run in a containerized environment.
    """
    try:
        collector = NvdNistCveCollector(configuration=ConfigLoader().to_daemon_config())
        collector.start()
    except Exception as e:
        print(f"Collector failed to start: {e}")
        raise


if __name__ == "__main__":

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
