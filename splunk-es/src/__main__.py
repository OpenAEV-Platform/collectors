"""Main entry point for the collector."""

import logging
import os
import sys


LOG_PREFIX = "[Main]"


def main() -> None:
    """Define the main function to run the collector."""
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"{LOG_PREFIX} Starting SplunkES collector...")
    except KeyboardInterrupt:
        logger.info(f"{LOG_PREFIX} Collector stopped by user (Ctrl+C)")
        os._exit(0)
    except Exception as e:
        logger.exception(f"{LOG_PREFIX} Fatal error starting collector: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
