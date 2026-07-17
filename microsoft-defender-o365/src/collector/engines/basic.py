import logging
import os

from pyoaev.apis.inject_expectation.model import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.client import OpenAEV
from pyoaev.helpers import OpenAEVDetectionHelper
from pyoaev.signatures.types import SignatureTypes
from src.collector.internals.oaev_uploaders import ExpectationUploader, TraceUploader
from src.collector.models.exception import (
    CollectorEngineConfigError,
    CollectorProcessingError,
    ExpectationProcessingError,
)
from src.collector.models.expectations import ExpectationResult, ExpectationSummary
from src.collector.models.source import Source
from src.collector.protocols.data_fetcher import DataFetcherProtocol
from src.collector.protocols.source_handler import SourceHandlerProtocol
from src.collector.types.collector import ExpectationsList, SourceConfig
from src.collector.utils.retroport_itertools import batched

LOG_PREFIX = "[BasicCollectorEngine]"


class BasicCollectorEngine:
    """
    Collector engine to be attached to a CollectorDaemon-based base collector.
    This collector is use-case agnostic and works with any source provided.
    """

    def __init__(
        self,
        name: str,
        collector_id: str,
        source: Source,
        source_handler: SourceHandlerProtocol,
        oaev_api: OpenAEV,
        batching: bool = False,
    ) -> None:
        self.name = name
        self.collector_id = collector_id

        if source and not isinstance(source, Source):
            raise TypeError("Source provided is not of type Source")
        self.source = source

        if source_handler and not isinstance(source_handler, SourceHandlerProtocol):
            raise TypeError(
                "Source handler provided does not follow source handler protocol"
            )
        self.source_handler = source_handler

        if oaev_api and not isinstance(oaev_api, OpenAEV):
            raise TypeError("OAEV API must be of OpenAEV type")
        self.oaev_api = oaev_api

        self.batching = batching

        self.logger = logging.getLogger(__name__)
        self.current_summary = ExpectationSummary()
        self.oaev_detection_helper = OpenAEVDetectionHelper(
            logger=self.logger,
            relevant_signatures_types=self.source.signatures,
        )
        self.expectation_uploader = ExpectationUploader(
            oaev_api=self.oaev_api,
            collector_id=self.collector_id,
        )
        self.trace_uploader = TraceUploader(
            oaev_api=self.oaev_api,
            collector_id=self.collector_id,
            collector_name=self.name,
        )

        self.configured = False

    @property
    def data_fetcher_model(self) -> type[DataFetcherProtocol]:
        return self.source.data_fetcher_model

    @property
    def signatures(self) -> list[SignatureTypes]:
        return self.source.signatures

    def configure_engine(self, config: SourceConfig, batching: bool = False) -> None:
        self.logger.info(
            f"{LOG_PREFIX} Supported signatures: {[sig.value for sig in self.signatures]}"
        )
        self.config = config
        self.batching = batching
        self._reset_summary()
        self.configured = True

    def _reset_summary(self) -> None:
        self.current_summary = ExpectationSummary(
            received=0,
            supported=0,
            processed=0,
            valid=0,
            total_processing_time=None,
        )

    @staticmethod
    def _filter_supported(expectations: ExpectationsList) -> ExpectationsList:
        return [
            exp
            for exp in expectations
            if isinstance(exp, (DetectionExpectation, PreventionExpectation))
        ]

    def _fetch_expectations(self) -> ExpectationsList:
        """Fetch expectations from OpenAEV.

        Returns:
            List of expectations.

        """
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
                f"{LOG_PREFIX} Fetched {len(expectations)} expectations, reversing order..."
            )
            expectations = list(reversed(expectations))
            return expectations
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error fetching expectations: {e}")
            return []

    def fetch_and_filter_expectations(self) -> ExpectationsList:
        """fetch expectations and filter out unsupported ones (wrong expectation types)"""
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
        if self.current_summary.unsupported:
            self.logger.debug(
                f"{LOG_PREFIX} Skipped {self.current_summary.unsupported} "
                f"unsupported expectation types"
            )
        return expectations

    def _process_batch(
        self,
        batch: ExpectationsList,
    ) -> list[ExpectationResult]:
        """
        Processing a single batch of expectations through the following steps:
        0. per expectation
        1. fetch the data using the data fetcher provided
        2. serialize each data as OAEVData
        3. group the expectation signatures per expectation
        4. check for a match between the grouped signatures (3.) with the OAEVData (2.)
        5. serialize each data as TraceData
        6. check for a match between the expectation (0.) and the data (1.)
        7. create the ExpectationResult using the previous match (6.) and the TraceData (5.)
        then return a list of all the results produced from the batch
        """
        batch_results = []

        try:
            # (1) fetch data
            self.logger.info(
                f"{LOG_PREFIX} Fetching data providing "
                f"data fetcher {self.data_fetcher_model} to source handler"
            )
            data = self.source_handler.get_source_data(
                self.data_fetcher_model(self.source_handler.config)
            )
        except Exception as err:  # per batch
            batch_results = [
                ExpectationResult.from_error(
                    ExpectationProcessingError(
                        f"Batch processing error during data fetching: {err}"
                    ),
                    expectation,
                )
                for expectation in batch
            ]
            self.logger.error(
                f"{LOG_PREFIX} Error processing batch during data fetching: {err}"
            )
            return batch_results

        error_count = 0
        for expectation in batch:
            try:
                matched = False
                traces = []
                for element in data:
                    # (2) serialize data as oaevdata
                    oaev_data = self.source_handler.serialize_as_oaevdata(element)

                    # (3) get the expectation signature groups
                    signature_groups = (
                        self.source_handler.get_expectation_signature_groups(
                            self.signatures, expectation
                        )
                    )

                    # (4) match signature (3) with oaevdata (2)
                    flag = self.source_handler.match_signature_groups_and_oaevdata(
                        signature_groups,
                        oaev_data,
                        self.oaev_detection_helper,
                    )
                    if flag:
                        # (5) serialize data as tracedata
                        trace = self.source_handler.serialize_as_tracedata(element)
                        traces.append(trace.model_dump())

                        # (6) match expectation (0) with sourcedata (1)
                        matchflag, breakflag = (
                            self.source_handler.match_expectation_and_sourcedata(
                                expectation, element
                            )
                        )
                        if matchflag:
                            matched = True
                        if breakflag:
                            break

                # (7) create results from step 6 + tracedata (5)
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
            f"{LOG_PREFIX} Batch processed: {len(batch_results)} results (including {error_count} errors))"
        )

        return batch_results

    def run_engine(self) -> None:
        """Process the callback for expectation processing.

        Executes a single processing cycle, handling expectations through the
        expectation manager and logging results. Handles keyboard interrupts
        and system exits gracefully.

        Raises:
            CollectorProcessingError: If processing cycle fails.
        """
        if not self.configured:
            raise CollectorEngineConfigError(
                "The collector engine is being ran before being configured."
                "Please, be sure to call configure_engine before calling run_engine."
            )

        self.logger.info(
            f"{LOG_PREFIX} Current summary reset before the new processing cycle"
        )
        self._reset_summary()

        try:
            self.logger.info(f"{LOG_PREFIX} Starting processing cycle...")

            # (0) fetch and filter expectations
            expectations = self.fetch_and_filter_expectations()

            if not expectations:
                self.logger.warning(f"{LOG_PREFIX} No expectations found to process")
                return

            results = []

            if self.batching:
                # using a retro-compatible batched
                # instead of itertools.batched due to python 3.11 support
                batches = batched(expectations, self.config.expectation_batch_size)
            else:
                batches = [
                    expectations,
                ]  # default: single giant batch of expectations

            for batch in batches:
                self.logger.info(
                    f"{LOG_PREFIX} Processing a batch of expectations of size {len(batch)}"
                )
                batch_results = self._process_batch(batch)
                results.extend(batch_results)

            self.current_summary.processed = len(results)
            self.current_summary.valid = sum(1 for result in results if result.is_valid)

            self.logger.info(
                f"{LOG_PREFIX} New batch processing completed: "
                f"{self.current_summary.valid} valid, "
                f"{self.current_summary.invalid} invalid, "
                f"{self.current_summary.unprocessed} skipped"
            )

            # upload expectations using results
            self.logger.debug(f"{LOG_PREFIX} Updating expectations in OpenAEV...")
            self.expectation_uploader.upload_data(results)

            # upload expectation traces using results
            self.logger.debug(f"{LOG_PREFIX} Creating and submitting traces...")
            self.trace_uploader.upload_data(results)

        except (KeyboardInterrupt, SystemExit):  # per batch processing cycle
            self.logger.info(f"{LOG_PREFIX} Collector stopping...")
            self.logger.info(
                f"{LOG_PREFIX} Current summary info: {self.current_summary}"
            )
            os._exit(0)
        except Exception as e:  # per batch processing cycle
            self.logger.error(f"{LOG_PREFIX} Error during processing cycle: {str(e)}")
            self.logger.info(
                f"{LOG_PREFIX} Current summary info: {self.current_summary}"
            )
            raise CollectorProcessingError(f"Processing error: {str(e)}") from e

        self.logger.info(
            f"{LOG_PREFIX} Processing cycle completed: {self.current_summary}"
        )
