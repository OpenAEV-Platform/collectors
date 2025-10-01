from nvd_nist_cve.nvd_nist_cve_collector import NvdNistCveCollector


def main():
    """
    Main entry point for the NVD NIST CVE collector.

    Creates and starts the collector daemon with default configuration.
    Designed to run in a containerized environment.
    """
    try:
        collector = NvdNistCveCollector()
        collector.start()
    except Exception as e:
        print(f"Collector failed to start: {e}")
        raise


if __name__ == "__main__":
    main()
