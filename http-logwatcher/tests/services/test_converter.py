from unittest.mock import MagicMock

import src.services.converter as module


def test_convert_logline_to_oaev():
    converter = module.HTTPLogwatcherConverter()
    logline = MagicMock()

    oaev_data = converter.convert_logline_to_oaev(logline)

    assert oaev_data["source_ipv4_address"] == logline.ip_source
