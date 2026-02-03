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
    for key in [
        "NVD_NIST_CVE_API_BASE_URL",
        "NVD_NIST_CVE_API_KEY",
        "NVD_NIST_CVE_START_YEAR",
    ]:
        if not os.environ.get(f"COLLECTOR_{key}") and os.environ.get(key):
            os.environ[f"COLLECTOR_{key}"] = os.environ.get(key)

    NvdNistCveCollector(configuration=ConfigLoader().to_daemon_config()).start()
