import unittest
from unittest.mock import MagicMock, patch

import src.collector.internals.resilient_uploader as module


class TestResilientUploader(unittest.TestCase):
    def test_resilient_uploader_init(self):
        data_name = "testitest"
        _prepare_bulk_data = MagicMock()
        _bulk_upload = MagicMock()
        _unpack_bulk_data = MagicMock()
        _individual_upload = MagicMock()

        resilient_uploader = module.ResilientUploader(
            data_name=data_name,
            _prepare_bulk_data=_prepare_bulk_data,
            _bulk_upload=_bulk_upload,
            _unpack_bulk_data=_unpack_bulk_data,
            _individual_upload=_individual_upload,
        )

        self.assertEqual(resilient_uploader.data_name, data_name)
        self.assertEqual(resilient_uploader._prepare_bulk_data, _prepare_bulk_data)
        self.assertEqual(resilient_uploader._bulk_upload, _bulk_upload)
        self.assertEqual(resilient_uploader._unpack_bulk_data, _unpack_bulk_data)
        self.assertEqual(resilient_uploader._individual_upload, _individual_upload)

    def test_resilient_uploader_prepare_bulk_data(self):
        data = [MagicMock(), MagicMock()]
        bulked_data = [MagicMock()]
        data_name = "testitest"
        _prepare_bulk_data = MagicMock()
        _prepare_bulk_data.return_value = (bulked_data, 1)
        _bulk_upload = MagicMock()
        _unpack_bulk_data = MagicMock()
        _individual_upload = MagicMock()

        resilient_uploader = module.ResilientUploader(
            data_name=data_name,
            _prepare_bulk_data=_prepare_bulk_data,
            _bulk_upload=_bulk_upload,
            _unpack_bulk_data=_unpack_bulk_data,
            _individual_upload=_individual_upload,
        )

        bulk_data = resilient_uploader.prepare_bulk_data(data)

        _prepare_bulk_data.assert_called_once_with(data)
        self.assertEqual(bulk_data, bulked_data)

    def test_resilient_uploader_bulk_upload_data_bulk_OK(self):
        bulk_data = [MagicMock(), MagicMock()]
        data_name = "testitest"
        _prepare_bulk_data = MagicMock()
        _bulk_upload = MagicMock()
        _unpack_bulk_data = MagicMock()
        _individual_upload = MagicMock()

        resilient_uploader = module.ResilientUploader(
            data_name=data_name,
            _prepare_bulk_data=_prepare_bulk_data,
            _bulk_upload=_bulk_upload,
            _unpack_bulk_data=_unpack_bulk_data,
            _individual_upload=_individual_upload,
        )

        resilient_uploader.bulk_upload_data(bulk_data)

        _bulk_upload.assert_called_once_with(bulk_data)
        _unpack_bulk_data.assert_not_called()
        _individual_upload.assert_not_called()

    def test_resilient_uploader_bulk_upload_data_individual_OK(self):
        bdata1 = MagicMock()
        bdata2 = MagicMock()
        bulk_data = [bdata1, bdata2]
        data_name = "testitest"
        _prepare_bulk_data = MagicMock()
        _bulk_upload = MagicMock()
        _bulk_upload.side_effect = Exception()
        _unpack_bulk_data = MagicMock()
        _unpack_bulk_data.return_value = [(1, bdata1), (2, bdata2)]
        _individual_upload = MagicMock()

        resilient_uploader = module.ResilientUploader(
            data_name=data_name,
            _prepare_bulk_data=_prepare_bulk_data,
            _bulk_upload=_bulk_upload,
            _unpack_bulk_data=_unpack_bulk_data,
            _individual_upload=_individual_upload,
        )

        resilient_uploader.bulk_upload_data(bulk_data)

        _bulk_upload.assert_called_once_with(bulk_data)
        _unpack_bulk_data.assert_called_once_with(bulk_data)
        self.assertEqual(_individual_upload._mock_call_count, 2)
        _individual_upload.assert_any_call(1, bdata1)
        _individual_upload.assert_called_with(2, bdata2)

    def test_resilient_uploader_bulk_upload_data_unpack_failure(self):
        bdata1 = MagicMock()
        bdata2 = MagicMock()
        bulk_data = [bdata1, bdata2]
        data_name = "testitest"
        _prepare_bulk_data = MagicMock()
        _bulk_upload = MagicMock()
        _bulk_upload.side_effect = Exception()
        _unpack_bulk_data = MagicMock()
        _unpack_bulk_data.side_effect = Exception()
        _individual_upload = MagicMock()

        resilient_uploader = module.ResilientUploader(
            data_name=data_name,
            _prepare_bulk_data=_prepare_bulk_data,
            _bulk_upload=_bulk_upload,
            _unpack_bulk_data=_unpack_bulk_data,
            _individual_upload=_individual_upload,
        )

        with self.assertRaises(Exception):
            resilient_uploader.bulk_upload_data(bulk_data)

        _bulk_upload.assert_called_once_with(bulk_data)
        _unpack_bulk_data.assert_called_once_with(bulk_data)

    @patch.object(module.ResilientUploader, "bulk_upload_data")
    @patch.object(module.ResilientUploader, "prepare_bulk_data")
    def test_resilient_uploader_upload_data(
        self, m_prepare_bulk_data, m_bulk_upload_data
    ):
        data = [MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        bdata1 = MagicMock()
        bdata2 = MagicMock()
        bulk_data = [bdata1, bdata2]
        m_prepare_bulk_data.return_value = bulk_data
        data_name = "testitest"
        _prepare_bulk_data = MagicMock()
        _bulk_upload = MagicMock()
        _unpack_bulk_data = MagicMock()
        _individual_upload = MagicMock()

        resilient_uploader = module.ResilientUploader(
            data_name=data_name,
            _prepare_bulk_data=_prepare_bulk_data,
            _bulk_upload=_bulk_upload,
            _unpack_bulk_data=_unpack_bulk_data,
            _individual_upload=_individual_upload,
        )

        resilient_uploader.upload_data(data)

        m_prepare_bulk_data.assert_called_once_with(data)
        m_bulk_upload_data.assert_called_once_with(bulk_data)

    @patch.object(module.ResilientUploader, "bulk_upload_data")
    @patch.object(module.ResilientUploader, "prepare_bulk_data")
    def test_resilient_uploader_upload_data_no_bulk_data(
        self, m_prepare_bulk_data, m_bulk_upload_data
    ):
        data = [MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        bulk_data = []
        m_prepare_bulk_data.return_value = bulk_data
        data_name = "testitest"
        _prepare_bulk_data = MagicMock()
        _bulk_upload = MagicMock()
        _unpack_bulk_data = MagicMock()
        _individual_upload = MagicMock()

        resilient_uploader = module.ResilientUploader(
            data_name=data_name,
            _prepare_bulk_data=_prepare_bulk_data,
            _bulk_upload=_bulk_upload,
            _unpack_bulk_data=_unpack_bulk_data,
            _individual_upload=_individual_upload,
        )

        resilient_uploader.upload_data(data)

        m_prepare_bulk_data.assert_called_once_with(data)
        m_bulk_upload_data.assert_not_called()
