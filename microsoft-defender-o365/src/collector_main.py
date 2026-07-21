"""
Microsoft Defender for Office 365 collector (MVP1 - email focused).

Chunk1 (#471): project architecture setup - a working skeleton collector with
no business logic implemented yet, wiring stub source elements into the
generic base collector so the collector appears in the OpenAEV catalog.
"""

import logging
import os
import sys

from src.collector.collector import BaseCollector
from src.collector.models.source import Source
from src.source.data_fetcher import MicrosoftDefenderO365DataFetcher
from src.source.signatures import SUPPORTED_SIGNATURES
from src.source.source_data import MicrosoftDefenderO365SourceData


def main() -> None:
    """
    defining a stub source, feeding it into the base collector,
    then starting said collector
    """
    logging.basicConfig(level=logging.ERROR)
    startup_logger = logging.getLogger(__name__)

    try:
        source = Source(
            data_fetcher_model=MicrosoftDefenderO365DataFetcher,
            source_data_model=MicrosoftDefenderO365SourceData,
            signatures=SUPPORTED_SIGNATURES,
        )
        base_collector = BaseCollector(
            name="Microsoft Defender O365 Collector",
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
