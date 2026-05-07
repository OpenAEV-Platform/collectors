import unittest
from unittest.mock import MagicMock, patch

import src.collector.collector as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
}


@patch.object(module, "BasicCollectorEngine", spec_set=module.BasicCollectorEngine)
@patch.object(module, "ConfigLoader")
class TestBaseCollector(unittest.TestCase):
    def test_minimal_init(self, m_configloader, m_basiccollectorengine):
        """"""
        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        name = "my collector"
        source = MagicMock(spec_set=module.Source)

        collector = module.BaseCollector(name=name, source=source)

        self.assertEqual(collector.name, name)
        self.assertEqual(collector.source, source)
        self.assertIsNotNone(collector.source_handler)
        self.assertIsNotNone(collector.engine)
        self.assertIsNotNone(collector.api)
        m_configloader.return_value.to_daemon_config.assert_called_once()
        m_basiccollectorengine.assert_called_with(
            name=name,
            collector_id=collector.get_id(),
            source=collector.source,
            source_handler=collector.source_handler,
            oaev_api=collector.api,
        )

    def test_init_with_custom_handler(self, m_configloader, m_basiccollectorengine):
        """"""
        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        name = "my collector"
        source = MagicMock(spec_set=module.Source)
        source_handler = MagicMock(spec_set=module.SourceHandler)

        collector = module.BaseCollector(
            name=name, source=source, source_handler=source_handler
        )

        self.assertEqual(collector.name, name)
        self.assertEqual(collector.source, source)
        self.assertEqual(source_handler, collector.source_handler)
        self.assertIsNotNone(collector.engine)
        self.assertIsNotNone(collector.api)
        m_configloader.return_value.to_daemon_config.assert_called_once()
        m_basiccollectorengine.assert_called_with(
            name=name,
            collector_id=collector.get_id(),
            source=collector.source,
            source_handler=collector.source_handler,
            oaev_api=collector.api,
        )

    def test_init_with_wrong_handler(self, m_configloader, m_basiccollectorengine):
        """"""
        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        name = "my collector"
        source = MagicMock(spec_set=module.Source)
        source_handler = MagicMock()

        with self.assertRaises(module.CollectorConfigError):
            module.BaseCollector(
                name=name, source=source, source_handler=source_handler
            )

    def test_init_with_alternative_engine(self, m_configloader, m_basiccollectorengine):
        """"""

        class NoRunEngine:
            def __init__(self, **kwargs):
                pass

            def configure_engine(self, config, batching=False):
                pass

            def run_engine(self):
                pass

        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        name = "my collector"
        source = MagicMock(spec_set=module.Source)
        engine_model = NoRunEngine

        collector = module.BaseCollector(
            name=name, source=source, engine_model=engine_model
        )

        self.assertEqual(collector.name, name)
        self.assertEqual(collector.source, source)
        self.assertEqual(engine_model, collector.engine_model)
        self.assertIsNotNone(collector.engine)
        self.assertIsNotNone(collector.api)
        m_configloader.return_value.to_daemon_config.assert_called_once()

    def test_init_with_wrong_engine(self, m_configloader, m_basiccollectorengine):
        """"""
        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        name = "my collector"
        source = MagicMock(spec_set=module.Source)
        engine_model = MagicMock()

        with self.assertRaises(module.CollectorConfigError):
            module.BaseCollector(name=name, source=source, engine_model=engine_model)

    @patch.object(module.CollectorDaemon, "_setup")
    def test_setup(
        self, m_collectordaemon_setup, m_configloader, m_basiccollectorengine
    ):
        """"""
        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        name = "my collector"
        source = MagicMock(spec_set=module.Source)
        source_handler = MagicMock(spec_set=module.SourceHandler)
        batching = True

        collector = module.BaseCollector(
            name=name, source=source, source_handler=source_handler
        )
        collector._setup(batching=batching)

        m_collectordaemon_setup.assert_called_once()
        m_basiccollectorengine.return_value.configure_engine.assert_called_with(
            collector.config.template, batching=batching
        )
