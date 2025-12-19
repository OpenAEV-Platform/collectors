from nvd_nist_cve.nvd_nist_cve_collector import NvdNistCveCollector
from nvd_nist_cve.configuration.config_loader import ConfigLoader


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
    NvdNistCveCollector(configuration=ConfigLoader().to_daemon_config()).start()

