"""Expectation uploader and expectation trace uploader based on the ResilientUploader object"""

from typing import Any, Iterable

from pyoaev.client import OpenAEV
from src.collector.internals.resilient_uploader import ResilientUploader
from src.collector.models.expectations import ExpectationTrace
from src.collector.types.internals import BulkData

LOG_PREFIX = "[Uploader]"


class ExpectationUploader(ResilientUploader):
    """ResilientUploader-based expectation uploader using the OpenAEV API"""

    def __init__(self, oaev_api: OpenAEV, collector_id: str):
        self.oaev_api = oaev_api
        self.collector_id = collector_id
        super().__init__(
            data_name="expectation",
            _prepare_bulk_data=self.expectation_prepare_bulk_data,
            _bulk_upload=self.expectation_bulk_upload,
            _unpack_bulk_data=self.expectation_unpack_bulk_data,
            _individual_upload=self.expectation_individual_upload,
        )

    def expectation_prepare_bulk_data(self, results: list[Any]) -> tuple[BulkData, int]:
        """
        convert a list of results into the required format
        for API's bulk_update later down the road
        """
        bulk_data = {}
        skipped_count = 0
        for result in results:
            try:
                # skipping result without expectation_id
                if not result.expectation_id:
                    skipped_count += 1
                    self.logger.debug(
                        f"{LOG_PREFIX} Skipping result without expectation_id"
                    )
                    continue

                # skipping result without expectation
                if not result.expectation:
                    skipped_count += 1
                    self.logger.debug(
                        f"{LOG_PREFIX} Skipping result {result.expectation_id} "
                        f"without expectation object"
                    )
                    continue

                bulk_data[result.expectation_id] = {
                    "collector_id": self.collector_id,
                    "result": result.to_result_text(),
                    "is_success": result.is_valid,
                }
            except Exception as err:
                self.logger.debug(f"{LOG_PREFIX} Skipping result due to error: {err}")
                skipped_count += 1

        return bulk_data, skipped_count

    def expectation_bulk_upload(self, bulk_data: BulkData) -> None:
        """expectation bulk update using the OpenAEV API"""
        self.oaev_api.inject_expectation.bulk_update(
            inject_expectation_input_by_id=bulk_data
        )

    def expectation_unpack_bulk_data(
        self, bulk_data: BulkData
    ) -> Iterable[tuple[str, Any]]:
        """unpack the default expectation bulk data format into a (index,data) iterable"""
        return bulk_data.items()

    def expectation_individual_upload(
        self, expectation_id: str, expectation_data: Any
    ) -> None:
        """expectation single update using the OpenAEV API"""
        self.oaev_api.inject_expectation.update(
            inject_expectation_id=expectation_id,
            inject_expectation=expectation_data,
        )


class TraceUploader(ResilientUploader):
    """ResilientUploader-based expectation trace uploader using the OpenAEV API"""

    def __init__(self, oaev_api: OpenAEV, collector_id: str, collector_name: str):
        self.oaev_api = oaev_api
        self.collector_id = collector_id
        self.collector_name = collector_name
        super().__init__(
            data_name="trace",
            _prepare_bulk_data=self.trace_prepare_bulk_data,
            _bulk_upload=self.trace_bulk_upload,
            _unpack_bulk_data=self.trace_unpack_bulk_data,
            _individual_upload=self.trace_individual_upload,
        )

    def trace_prepare_bulk_data(self, results: list[Any]) -> tuple[BulkData, int]:
        """
        convert a list of results into the required format
        for API's bulk_create later down the road
        """
        valid_results = [
            result for result in results if result.is_valid and result.matched_alerts
        ]
        if not valid_results:
            return [], len(results)

        traces = []
        skipped_count = 0
        for result in results:
            try:
                # skipping result without expectation_id
                if not result.expectation_id:
                    self.logger.debug(
                        f"{LOG_PREFIX} Skipping result without expectation_id"
                    )
                    skipped_count += 1
                    continue

                trace = ExpectationTrace.from_result(
                    result, self.collector_id, self.collector_name
                )
                traces.append(trace)
            except Exception as err:
                self.logger.debug(f"{LOG_PREFIX} Skipping result due to error: {err}")
                skipped_count += 1

        return traces, skipped_count

    def trace_bulk_upload(self, traces: BulkData) -> None:
        """expectation trace bulk upload using the OpenAEV API"""
        self.oaev_api.inject_expectation_trace.bulk_create(
            payload={"expectation_traces": [trace.to_api_dict() for trace in traces]}
        )

    def trace_unpack_bulk_data(self, traces: BulkData) -> Iterable[tuple[int, Any]]:
        """unpack the default expectation trace bulk data format into a (index,data) iterable"""
        return enumerate(traces, 1)

    def trace_individual_upload(self, _: Any, trace: Any) -> None:
        """expectation trace single upload using the OpenAEV API"""
        self.oaev_api.inject_expectation_trace.create(trace.to_api_dict())
