"""
Template collector meant to easier collector development,
based on the distinction between the normalized collector engine
and the custom source related to the implemented tool/service
"""

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
        os._exit(0)
    except Exception as err:
        print(err)
        sys.exit(1)
