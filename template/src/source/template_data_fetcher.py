from src.collector.types.collector import CustomConfig
from src.source.template_source_data import TemplateSourceData


class TemplateDataFetcher:
    """
    Placeholder data fetcher class, meant to follow the data fetcher protocol
    """

    def __init__(self, custom_config: CustomConfig) -> None:
        """attaching the custom configuration to the data fetcher object"""
        self.config = custom_config

    def fetch_data(self) -> list[TemplateSourceData]:
        """return placeholder data in the source data format"""
        return [TemplateSourceData(), TemplateSourceData(), TemplateSourceData()]
