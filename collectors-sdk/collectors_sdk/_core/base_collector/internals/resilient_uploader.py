"""A generic class for resilient upload with bulk + individual fallback."""

import logging
from typing import Any

from collectors_sdk._core.base_collector.models.exception import (
    APIError,
    BulkPreparationError,
    BulkUploadError,
)
from collectors_sdk._core.base_collector.types.internals import (
    BulkData,
    BulkUploadFunction,
    IndividualUploadFunction,
    PrepareBulkFunction,
    UnpackBulkFunction,
)

LOG_PREFIX = "[ResilientUploader]"


class ResilientUploader:
    """A generic bulk uploader with a fallback method for single upload."""

    def __init__(
        self,
        data_name: str,
        _prepare_bulk_data: PrepareBulkFunction,
        _bulk_upload: BulkUploadFunction,
        _unpack_bulk_data: UnpackBulkFunction,
        _individual_upload: IndividualUploadFunction,
    ):
        self.logger = logging.getLogger(__name__)
        self.data_name = data_name
        self._prepare_bulk_data = _prepare_bulk_data
        self._bulk_upload = _bulk_upload
        self._unpack_bulk_data = _unpack_bulk_data
        self._individual_upload = _individual_upload

    def prepare_bulk_data(self, data: list[Any]) -> BulkData:
        try:
            bulk_data, skipped_count = self._prepare_bulk_data(data)
        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Failure during bulk data preparation: {err}")
            raise BulkPreparationError(
                f"Error in bulk {self.data_name} preparation: {err}"
            ) from err

        if skipped_count > 0:
            self.logger.debug(
                f"{LOG_PREFIX} Skipped {skipped_count} input data "
                f"during bulk {self.data_name} preparation"
            )
        return bulk_data

    def bulk_upload_data(self, bulk_data: BulkData) -> None:
        try:
            self.logger.debug(f"{LOG_PREFIX} Attempting bulk upload...")
            self._bulk_upload(bulk_data)
            self.logger.info(
                f"{LOG_PREFIX} Successfully bulk upload {len(bulk_data)} {self.data_name}"
            )
        except Exception as bulk_error:
            self.logger.warning(
                f"{LOG_PREFIX} Bulk upload failed, falling back to individual updates: {bulk_error}"
            )
            try:
                success_count = 0
                error_count = 0
                for index, data in self._unpack_bulk_data(bulk_data):
                    try:
                        self._individual_upload(index, data)
                        success_count += 1
                    except APIError as api_err:
                        error_count += 1
                        self.logger.error(
                            f"{LOG_PREFIX} Failed to update {self.data_name} index {index}: {api_err}"
                        )
                    except Exception as err:
                        error_count += 1
                        self.logger.error(
                            f"{LOG_PREFIX} Unexpected error updating {self.data_name} index {index}: {err}"
                        )
                self.logger.info(
                    f"{LOG_PREFIX} Individual uploads completed: "
                    f"{success_count} successful, {error_count} failed"
                )
            except Exception as fallback_error:
                raise BulkUploadError(
                    f"Both bulk and individual uploads failed: {fallback_error}"
                ) from fallback_error

    def upload_data(self, data: list[Any]) -> None:
        if not data:
            self.logger.debug(
                f"{LOG_PREFIX} No {self.data_name} to upload, skipping"
            )
            return

        try:
            bulk_data = self.prepare_bulk_data(data)
            if not bulk_data:
                self.logger.debug(f"{LOG_PREFIX} No bulk {self.data_name} produced")
                return
            self.bulk_upload_data(bulk_data)
        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Bulk {self.data_name} upload failed: {err}")
            raise BulkUploadError(f"Error in bulk {self.data_name} upload: {err}") from err
