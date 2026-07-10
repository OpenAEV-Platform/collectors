"""
Template collector meant to ease collector development,
based on the distinction between the normalized collector engine
and the custom source related to the implemented tool/service
"""

import logging
import os
import sys

from src.collector.collector import BaseCollector
from src.collector.models.source import Source
from src.source.template_data_fetcher import TemplateDataFetcher
from src.source.template_signatures import SUPPORTED_SIGNATURES
from src.source.template_source_data import TemplateSourceData


def main() -> None:
    """
    defining a source, feeding it into the base collector,
    then starting said collector
    """
    logging.basicConfig(level=logging.ERROR)
    startup_logger = logging.getLogger(__name__)

    try:
        source = Source(
            data_fetcher_model=TemplateDataFetcher,
            source_data_model=TemplateSourceData,
            signatures=SUPPORTED_SIGNATURES,
        )
        base_collector = BaseCollector(
            name="Template collector",
            source=source,
        )
        base_collector.start()
    except KeyboardInterrupt:
        startup_logger.warning("Keyboard interruption, exiting with exit code 0...")
        os._exit(0)
    except Exception as err:
        startup_logger.error(
            f"Exception caught in the main function: {type(err).__name__} - {err}"
        )
        startup_logger.warning("Exiting with exit code 1...")
        sys.exit(1)
