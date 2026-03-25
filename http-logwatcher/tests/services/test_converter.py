import src.services.converter as module


def test_convert_logline_to_oaev():
    converter = module.HTTPLogwatcherConverter()
    logline = None

    oaev_data = converter.convert_logline_to_oaev(logline)

    assert oaev_data == {}
