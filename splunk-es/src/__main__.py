"""Main entry point for the collector."""

import logging
import os
import sys

from src.collector import Collector
from src.collector.exception import CollectorConfigError

LOG_PREFIX = "[Main]"


def main() -> None:
    """Define the main function to run the collector."""
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"{LOG_PREFIX} Starting SplunkES collector...")
        collector = Collector()
        collector.start()
    except KeyboardInterrupt:
        logger.info(f"{LOG_PREFIX} Collector stopped by user (Ctrl+C)")
        os._exit(0)
    except CollectorConfigError as e:
        logger.error(f"{LOG_PREFIX} Configuration error: {e}")
        sys.exit(2)
    except Exception as e:
        logger.exception(f"{LOG_PREFIX} Fatal error starting collector: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
