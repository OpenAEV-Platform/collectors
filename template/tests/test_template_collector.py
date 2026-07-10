import unittest
from unittest.mock import patch

import src.template_collector as module


class TestTemplateCollector(unittest.TestCase):
    @patch.object(module, "BaseCollector")
    @patch.object(module, "Source")
    @patch.object(module, "SUPPORTED_SIGNATURES")
    @patch.object(module, "TemplateSourceData")
    @patch.object(module, "TemplateDataFetcher")
    def test_template_collector_main(
        self,
        m_templatedatafetcher,
        m_templatesourcedata,
        m_supportedsignatures,
        m_source,
        m_basecollector,
    ):
        module.main()

        m_source.assert_called_once_with(
            data_fetcher_model=m_templatedatafetcher,
            source_data_model=m_templatesourcedata,
            signatures=m_supportedsignatures,
        )
        m_basecollector.assert_called_once_with(
            name="Template collector",
            source=m_source.return_value,
        )
        m_basecollector.return_value.start.assert_called_once()
