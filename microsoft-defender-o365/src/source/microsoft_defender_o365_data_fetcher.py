from src.collector.types.collector import SourceConfig
from src.source.microsoft_defender_o365_source_data import (
    MicrosoftDefenderO365SourceData,
)


class MicrosoftDefenderO365DataFetcher:
    """
    Placeholder data fetcher class, meant to follow the data fetcher protocol
    """

    def __init__(self, source_config: SourceConfig) -> None:
        """attaching the source configuration to the data fetcher object"""
        self.config = source_config

    def fetch_data(self) -> list[MicrosoftDefenderO365SourceData]:
        """return placeholder data in the source data format"""
        return [
            MicrosoftDefenderO365SourceData(),
            MicrosoftDefenderO365SourceData(),
            MicrosoftDefenderO365SourceData(),
        ]
