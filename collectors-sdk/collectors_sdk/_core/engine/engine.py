"""BasicCollectorEngine — the core processing pipeline."""

from __future__ import annotations

import logging
import os
from itertools import batched
from typing import Any

from collectors_sdk._core.errors import (
    CollectorEngineConfigError,
    CollectorProcessingError,
    ExpectationProcessingError,
)
from collectors_sdk._core.models.expectations import (
    ExpectationResult,
    ExpectationSummary,
)

LOG_PREFIX = "[BasicCollectorEngine]"

__all__ = ["BasicCollectorEngine"]


class BasicCollectorEngine:
    """Use-case agnostic collector engine for expectation processing.

    Implements the 7-step processing pipeline:
    fetch → filter → batch → (fetch data, serialize, match, build results) → upload.
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
    def data_fetcher_model(self) -> type[Any]:
        """The data fetcher class from the source."""
        return self.source.data_fetcher_model  # type: ignore[no-any-return]

    @property
    def signatures(self) -> list[Any]:
        """The signature types from the source."""
        return self.source.signatures  # type: ignore[no-any-return]

    def configure_engine(self, config: Any, batching: bool = False) -> None:
        """Configure the engine before running."""
        self.logger.info(
            f"{LOG_PREFIX} Supported signatures: "
            f"{[getattr(s, 'value', str(s)) for s in self.signatures]}"
        )
        self.config = config
        self.batching = batching
        self._reset_summary()
        self.configured = True

    def _reset_summary(self) -> None:
        self.current_summary = ExpectationSummary(
            received=0, supported=0, processed=0, valid=0, total_processing_time=None
        )

    def _filter_supported(self, expectations: list[Any]) -> list[Any]:
        """Filter out unsupported expectation types."""
        return [
            exp
            for exp in expectations
            if type(exp).__name__ in ("DetectionExpectation", "PreventionExpectation")
        ]

    def _fetch_expectations(self) -> list[Any]:
        """Fetch expectations from the OpenAEV API."""
        self.logger.debug(
            f"{LOG_PREFIX} Fetching expectations for collector: {self.collector_id}"
        )
        try:
            expectations = (
                self.oaev_api.inject_expectation.expectations_models_for_source(
                    source_id=self.collector_id
                )
            )
            self.logger.debug(
                f"{LOG_PREFIX} Fetched {len(expectations)} expectations"
            )
            return list(reversed(expectations))
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error fetching expectations: {e}")
            return []

    def fetch_and_filter_expectations(self) -> list[Any]:
        """Fetch and filter expectations, updating the summary."""
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

    def _process_batch(self, batch_list: list[Any]) -> list[ExpectationResult]:
        """Process a single batch of expectations through the 7-step pipeline."""
        batch_results: list[ExpectationResult] = []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Fetching data providing "
                f"data fetcher {self.data_fetcher_model} to source handler"
            )
            data = self.source_handler.get_source_data(
                self.data_fetcher_model(self.source_handler.config)
            )
        except Exception as err:
            batch_results = [
                ExpectationResult.from_error(
                    ExpectationProcessingError(
                        f"Batch processing error during data fetching: {err}"
                    ),
                    expectation,
                )
                for expectation in batch_list
            ]
            self.logger.error(
                f"{LOG_PREFIX} Error processing batch during data fetching: {err}"
            )
            return batch_results

        error_count = 0
        for expectation in batch_list:
            try:
                matched = False
                traces: list[dict[str, Any]] = []
                for element in data:
                    oaev_data = self.source_handler.serialize_as_oaevdata(element)
                    signature_groups = (
                        self.source_handler.get_expectation_signature_groups(
                            self.signatures, expectation
                        )
                    )
                    flag = self.source_handler.match_signature_groups_and_oaevdata(
                        signature_groups, oaev_data, None
                    )
                    if flag:
                        trace = self.source_handler.serialize_as_tracedata(element)
                        traces.append(trace.model_dump())
                        matchflag, breakflag = (
                            self.source_handler.match_expectation_and_sourcedata(
                                expectation, element
                            )
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
                    ExpectationProcessingError(f"Processing error: {err}"),
                    expectation,
                )
                self.logger.error(f"{LOG_PREFIX} Processing batch: {err}")
                error_count += 1
            batch_results.append(result)

        self.logger.info(
            f"{LOG_PREFIX} Batch processed: {len(batch_results)} results "
            f"(including {error_count} errors)"
        )
        return batch_results

    def run_engine(self) -> None:
        """Execute a single processing cycle.

        Raises:
            CollectorEngineConfigError: If called before configure_engine().
            CollectorProcessingError: If the processing cycle fails.
        """
        if not self.configured:
            raise CollectorEngineConfigError(
                "The collector engine is being ran before being configured. "
                "Please, be sure to call configure_engine before calling run_engine."
            )

        self.logger.info(
            f"{LOG_PREFIX} Current summary reset before the new processing cycle"
        )
        self._reset_summary()

        try:
            self.logger.info(f"{LOG_PREFIX} Starting processing cycle...")
            expectations = self.fetch_and_filter_expectations()

            if not expectations:
                self.logger.warning(
                    f"{LOG_PREFIX} No expectations found to process"
                )
                return

            results: list[ExpectationResult] = []

            if self.batching:
                batches: Any = batched(
                    expectations,
                    getattr(self.config, "expectation_batch_size", 50),
                )
            else:
                batches = [expectations]

            for batch_items in batches:
                batch_list = list(batch_items)
                self.logger.info(
                    f"{LOG_PREFIX} Processing a batch of expectations "
                    f"of size {len(batch_list)}"
                )
                batch_results = self._process_batch(batch_list)
                results.extend(batch_results)

            self.current_summary.processed = len(results)
            self.current_summary.valid = sum(
                1 for result in results if result.is_valid
            )

            self.logger.info(
                f"{LOG_PREFIX} Processing completed: "
                f"{self.current_summary.valid} valid, "
                f"{self.current_summary.invalid} invalid"
            )

        except (KeyboardInterrupt, SystemExit):
            self.logger.info(f"{LOG_PREFIX} Collector stopping...")
            os._exit(0)
        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Error during processing cycle: {e}"
            )
            raise CollectorProcessingError(
                f"Processing error: {e}"
            ) from e

        self.logger.info(
            f"{LOG_PREFIX} Processing cycle completed: {self.current_summary}"
        )
