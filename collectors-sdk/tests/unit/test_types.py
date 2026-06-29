"""RED tests for type aliases."""

from __future__ import annotations

from collectors_sdk import (
    BulkData,
    BulkUploadFunction,
    CustomConfig,
    ExpectationsList,
    IndividualUploadFunction,
    PrepareBulkFunction,
    SignatureGroups,
    UnpackBulkFunction,
)


class TestTypeAliases:
    """Verify all 8 type aliases are importable."""

    def test_custom_config_exists(self) -> None:
        assert CustomConfig is not None

    def test_expectations_list_exists(self) -> None:
        assert ExpectationsList is not None

    def test_signature_groups_exists(self) -> None:
        assert SignatureGroups is not None

    def test_bulk_data_exists(self) -> None:
        assert BulkData is not None

    def test_prepare_bulk_function_exists(self) -> None:
        assert PrepareBulkFunction is not None

    def test_bulk_upload_function_exists(self) -> None:
        assert BulkUploadFunction is not None

    def test_unpack_bulk_function_exists(self) -> None:
        assert UnpackBulkFunction is not None

    def test_individual_upload_function_exists(self) -> None:
        assert IndividualUploadFunction is not None
