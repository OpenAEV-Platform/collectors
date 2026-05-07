from src.source.template_source_data import TemplateSourceData


class TemplateDataFetcher:
    """
    Placeholder data fetcher class, meant to follow the data fetcher protocol
    """

    def fetch_data(self):
        """return placeholder data in the source data format"""
        return [TemplateSourceData(), TemplateSourceData(), TemplateSourceData()]
