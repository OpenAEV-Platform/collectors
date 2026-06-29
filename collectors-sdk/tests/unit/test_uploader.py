"""RED tests for ResilientUploader (internal)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from collectors_sdk import BulkUploadError


class TestResilientUploader:
    """ResilientUploader generic upload strategy."""

    def _make_uploader(
        self,
        prepare: Any = None,
        bulk: Any = None,
        unpack: Any = None,
        individual: Any = None,
    ) -> Any:
        from collectors_sdk._core.engine.uploader import ResilientUploader

        return ResilientUploader(
            data_name="test",
            _prepare_bulk_data=prepare or MagicMock(return_value=({}, 0)),
            _bulk_upload=bulk or MagicMock(),
            _unpack_bulk_data=unpack or MagicMock(return_value=[]),
            _individual_upload=individual or MagicMock(),
        )

    def test_empty_list_is_noop(self) -> None:
        bulk_fn = MagicMock()
        uploader = self._make_uploader(bulk=bulk_fn)
        uploader.upload_data([])
        bulk_fn.assert_not_called()

    def test_bulk_success(self) -> None:
        prepare = MagicMock(return_value=({"a": 1}, 0))
        bulk = MagicMock()
        uploader = self._make_uploader(prepare=prepare, bulk=bulk)
        uploader.upload_data([MagicMock()])
        bulk.assert_called_once()

    def test_bulk_fails_fallback_individual(self) -> None:
        prepare = MagicMock(return_value=({"a": 1}, 0))
        bulk = MagicMock(side_effect=Exception("bulk failed"))
        unpack = MagicMock(return_value=[("a", 1)])
        individual = MagicMock()
        uploader = self._make_uploader(
            prepare=prepare, bulk=bulk, unpack=unpack, individual=individual
        )
        uploader.upload_data([MagicMock()])
        individual.assert_called_once()

    def test_prepare_fails_raises_bulk_preparation_error(self) -> None:
        prepare = MagicMock(side_effect=Exception("prepare failed"))
        uploader = self._make_uploader(prepare=prepare)
        with pytest.raises(BulkUploadError):
            uploader.upload_data([MagicMock()])

    def test_both_fail_raises_bulk_upload_error(self) -> None:
        prepare = MagicMock(return_value=({"a": 1}, 0))
        bulk = MagicMock(side_effect=Exception("bulk failed"))
        unpack = MagicMock(side_effect=Exception("unpack failed"))
        uploader = self._make_uploader(prepare=prepare, bulk=bulk, unpack=unpack)
        with pytest.raises(BulkUploadError):
            uploader.upload_data([MagicMock()])
