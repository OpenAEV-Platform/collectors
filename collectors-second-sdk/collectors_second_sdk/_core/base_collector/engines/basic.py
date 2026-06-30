"""BasicCollectorEngine — use-case agnostic collector engine."""

import logging
import os
from typing import Any

from xtm_oaev_sdk import SignatureTypes

from collectors_second_sdk._core.base_collector.internals.resilient_uploader import ResilientUploader
from collectors_second_sdk._core.base_collector.models.exception import (
    CollectorEngineConfigError,
    CollectorProcessingError,
    ExpectationProcessingError,
)
from collectors_second_sdk._core.base_collector.models.expectations import (
    ExpectationResult,
    ExpectationSummary,
)

from collectors_second_sdk._core.base_collector.protocols.data_fetcher import DataFetcherProtocol

from collectors_second_sdk._core.base_collector.types.collector import CustomConfig, ExpectationsList
from collectors_second_sdk._core.base_collector.utils.retroport_itertools import batched

LOG_PREFIX = "[BasicCollectorEngine]"


class BasicCollectorEngine:
    """Collector engine to be attached to a CollectorDaemon-based base collector.

    This collector is use-case agnostic and works with any source provided.
    """

    def __init__(
        self,
        name: str,
        collector_id: str,
        source: Any,
        source_handler: Any,
        oaev_api: Any,
        batching: bool = False,
    ) -> None:
        self.name = name
        self.collector_id = collector_id
        self.source = source
        self.source_handler = source_handler
        self.oaev_api = oaev_api
        self.batching = batching
        self.logger = logging.getLogger(__name__)
        self.current_summary = ExpectationSummary()
        self.configured = False

    @property
    def data_fetcher_model(self) -> type[DataFetcherProtocol]:
        return self.source.data_fetcher_model

    @property
    def signatures(self) -> list[SignatureTypes]:
        return self.source.signatures

    def configure_engine(self, config: CustomConfig, batching: bool = False) -> None:
        self.logger.info(
            f"{LOG_PREFIX} Supported signatures: {[sig.value for sig in self.signatures]}"
        )
        self.config = config
        self.batching = batching
        self._reset_summary()
        self.configured = True

    def _reset_summary(self) -> None:
        self.current_summary = ExpectationSummary()

    def _filter_supported(self, expectations: ExpectationsList) -> ExpectationsList:
        """Filter out unsupported expectation types."""
        return [
            exp
            for exp in expectations
            if type(exp).__name__ in ("DetectionExpectation", "PreventionExpectation")
        ]

    def _fetch_expectations(self) -> ExpectationsList:
        self.logger.debug(f"{LOG_PREFIX} Fetching expectations for collector: {self.collector_id}")
        try:
            expectations = self.oaev_api.inject_expectation.expectations_models_for_source(
                source_id=self.collector_id
            )
            self.logger.debug(f"{LOG_PREFIX} Fetched {len(expectations)} expectations, reversing order...")
            return list(reversed(expectations))
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error fetching expectations: {e}")
            return []

    def fetch_and_filter_expectations(self) -> ExpectationsList:
        self.logger.debug(f"{LOG_PREFIX} Fetching expectations from OpenAEV...")
        expectations = self._fetch_expectations()
        self.current_summary.received = len(expectations)
        expectations = self._filter_supported(expectations)
        self.current_summary.supported = len(expectations)

        self.logger.info(
            f"{LOG_PREFIX} Received {self.current_summary.received} expectations: "
            f"{self.current_summary.supported} supported, "
            f"{self.current_summary.unsupported} skipped"
        )
        return expectations

    def _process_batch(self, batch: ExpectationsList) -> list[ExpectationResult]:
        batch_results = []
        try:
            data = self.source_handler.get_source_data(
                self.data_fetcher_model(self.source_handler.config)
            )
        except Exception as err:
            return [
                ExpectationResult.from_error(
                    ExpectationProcessingError(f"Batch processing error during data fetching: {err}"),
                    expectation,
                )
                for expectation in batch
            ]

        for expectation in batch:
            try:
                matched = False
                traces = []
                for element in data:
                    oaev_data = self.source_handler.serialize_as_oaevdata(element)
                    signature_groups = self.source_handler.get_expectation_signature_groups(
                        self.signatures, expectation
                    )
                    flag = self.source_handler.match_signature_groups_and_oaevdata(
                        signature_groups, oaev_data, None
                    )
                    if flag:
                        trace = self.source_handler.serialize_as_tracedata(element)
                        traces.append(trace.model_dump())
                        matchflag, breakflag = self.source_handler.match_expectation_and_sourcedata(
                            expectation, element
                        )
                        if matchflag:
                            matched = True
                        if breakflag:
                            break

                result = ExpectationResult(
                    expectation_id=str(expectation.inject_expectation_id),
                    is_valid=matched,
                    expectation=expectation,
                    matched_alerts=traces,
                )
            except Exception as err:
                result = ExpectationResult.from_error(
                    ExpectationProcessingError(f"Processing error: {err}"), expectation
                )
            batch_results.append(result)
        return batch_results

    def run_engine(self) -> None:
        if not self.configured:
            raise CollectorEngineConfigError(
                "The collector engine must be configured before running. "
                "Call configure_engine first."
            )

        self._reset_summary()
        try:
            self.logger.info(f"{LOG_PREFIX} Starting processing cycle...")
            expectations = self.fetch_and_filter_expectations()

            if not expectations:
                self.logger.warning(f"{LOG_PREFIX} No expectations found to process")
                return

            results = []
            if self.batching:
                batches = batched(expectations, self.config.expectation_batch_size)
            else:
                batches = [expectations]

            for batch in batches:
                batch_results = self._process_batch(batch)
                results.extend(batch_results)

            self.current_summary.processed = len(results)
            self.current_summary.valid = sum(1 for r in results if r.is_valid)

            self.logger.info(
                f"{LOG_PREFIX} Processing completed: "
                f"{self.current_summary.valid} valid, "
                f"{self.current_summary.invalid} invalid, "
                f"{self.current_summary.unprocessed} skipped"
            )

        except (KeyboardInterrupt, SystemExit):
            self.logger.info(f"{LOG_PREFIX} Collector stopping...")
            os._exit(0)
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error during processing cycle: {str(e)}")
            raise CollectorProcessingError(f"Processing error: {str(e)}") from e

        self.logger.info(f"{LOG_PREFIX} Processing cycle completed: {self.current_summary}")
