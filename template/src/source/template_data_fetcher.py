from src.collector.types.collector import SourceConfig
from src.source.template_source_data import TemplateSourceData


class TemplateDataFetcher:
    """
    Placeholder data fetcher class, meant to follow the data fetcher protocol
    """

    def __init__(self, source_config: SourceConfig) -> None:
        """attaching the source configuration to the data fetcher object"""
        self.config = source_config

    def fetch_data(self) -> list[TemplateSourceData]:
        """return placeholder data in the source data format"""
        return [TemplateSourceData(), TemplateSourceData(), TemplateSourceData()]
