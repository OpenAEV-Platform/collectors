"""Core collector."""

import os

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    LoggingExpectation,
)
from pyoaev.daemons import CollectorDaemon  # type: ignore[import-untyped]
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from src.services.expectation_service import SentinelOneExpectationService
from src.services.logging_fetch import fetch_logging_events
from src.services.logging_query import build_logging_query
from src.services.logging_trace import build_logging_trace
from src.services.trace_service import SentinelOneTraceService
from src.services.utils import SentinelOneConfig

from .exception import (
    CollectorConfigError,
    CollectorProcessingError,
    CollectorSetupError,
)
from .expectation_handler import GenericExpectationHandler
from .expectation_manager import GenericExpectationManager
from .logging_manager import LoggingManager

LOG_PREFIX = "[Collector]"
# PREVENTION stays declared so the platform's view of the collector is unchanged.
ALERT_EXPECTATION_TYPES = ["DETECTION", "PREVENTION"]
LOGGING_EXPECTATION_TYPE = "LOGGING"


def _signature_dicts(expectation: LoggingExpectation) -> list[dict[str, str]]:
    """List the signatures of an expectation as the query builder reads them.

    Args:
        expectation: The LOGGING expectation.

    Returns:
        One ``{"type", "value"}`` mapping per signature, as for Detection.

    """
    return [
        {"type": signature.type.value, "value": signature.value}
        for signature in expectation.inject_expectation_signatures
    ]


class Collector(CollectorDaemon):  # type: ignore[misc]
    """Generic Collector using service provider pattern.

    This collector is use-case agnostic and works with any service provider.
    """

    def __init__(self) -> None:
        """Initialize the collector.

        Raises:
            CollectorConfigError: If collector initialization fails.

        """
        try:
            self.config = SentinelOneConfig()
            self.config_instance = self.config.load
            # "is True": a mocked config must not turn Logging on.
            self.logging_enabled = (
                self.config_instance.sentinelone.logging_enabled is True
            )

            super().__init__(
                configuration=self.config_instance.to_daemon_config(),
                callback=self._process_callback,
                collector_type="openaev_sentinelone",
                supported_expectation_types=self._declared_expectation_types(),
            )

            self.logger.info(  # type: ignore[has-type]
                f"{LOG_PREFIX} SentinelOne Collector initialized successfully"
            )

        except Exception as err:
            import logging

            logging.basicConfig(level=logging.ERROR)
            self.logger = logging.getLogger(__name__)
            raise CollectorConfigError(
                f"Failed to initialize the collector: {err}"
            ) from err

    def _setup(self) -> None:
        """Set up the collector.

        Initializes SentinelOne services, expectation handler, expectation manager,
        and OpenAEV detection helper. Sets up the collector for processing expectations.

        Raises:
            CollectorSetupError: If collector setup fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting collector setup...")

            super()._setup()

            self.logger.debug(f"{LOG_PREFIX} Initializing SentinelOne services...")

            self.sentinelone_service = SentinelOneExpectationService(
                config=self.config_instance
            )

            self.trace_service = SentinelOneTraceService(self.config_instance)

            self.expectation_handler = GenericExpectationHandler(
                self.sentinelone_service
            )

            self.expectation_manager = GenericExpectationManager(
                oaev_api=self.api,
                collector_id=self.get_id(),
                expectation_handler=self.expectation_handler,
                trace_service=self.trace_service,
            )

            self.logging_manager = None
            if self.logging_enabled:
                self._setup_logging()
            else:
                self.logger.info(f"{LOG_PREFIX} Logging expectations disabled")

            supported_signatures = self.sentinelone_service.get_supported_signatures()
            self.oaev_detection_helper = OpenAEVDetectionHelper(
                logger=self.logger,
                relevant_signatures_types=supported_signatures,
            )

            self.logger.info(f"{LOG_PREFIX} Collector setup completed successfully")
            self.logger.info(
                f"{LOG_PREFIX} Supported signatures: {[sig.value for sig in supported_signatures]}"
            )

            service_info = self.sentinelone_service.get_service_info()
            self.logger.debug(f"{LOG_PREFIX} Service info: {service_info}")

        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Collector setup failed: {err}")
            raise CollectorSetupError(f"Failed to setup the collector: {err}") from err

    def _process_callback(self) -> None:
        """Process the callback for expectation processing.

        Executes a single processing cycle, handling expectations through the
        expectation manager and logging results. Handles keyboard interrupts
        and system exits gracefully.

        Raises:
            CollectorProcessingError: If processing cycle fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting processing cycle...")
            self.logger.debug(
                f"{LOG_PREFIX} Processing expectations using SentinelOne services"
            )

            try:
                results = self.expectation_manager.process_expectations(
                    detection_helper=self.oaev_detection_helper
                )
            except Exception:
                # Logging runs even when Detection failed: one pass must never
                # stop the other. A stop request (Ctrl+C) skips it.
                self._run_logging_pass()
                raise

            self.logger.info(
                f"{LOG_PREFIX} Processing cycle completed: {results.processed} total, "
                f"{results.valid} valid, {results.invalid} invalid, "
                f"{results.skipped} skipped"
            )
            # Logging runs after Detection, so that Logging searches never
            # delay the Detection results.
            self._run_logging_pass()

        except KeyboardInterrupt, SystemExit:
            self.logger.info(f"{LOG_PREFIX} Collector stopping...")
            os._exit(0)
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error during processing cycle: {str(e)}")
            raise CollectorProcessingError(f"Processing error: {str(e)}") from e

    def _declared_expectation_types(self) -> list[str]:
        """List the expectation types declared to the platform.

        Returns:
            DETECTION and PREVENTION, plus LOGGING when Logging is enabled.

        """
        if self.logging_enabled:
            return [*ALERT_EXPECTATION_TYPES, LOGGING_EXPECTATION_TYPE]
        return list(ALERT_EXPECTATION_TYPES)

    def _setup_logging(self) -> None:
        """Create the Logging manager; on failure, run Detection only.

        The collector is already registered with LOGGING at this point: if
        the Logging pass cannot be set up, LOGGING is withdrawn so that the
        platform stops waiting for its results.
        """
        try:
            self.logging_manager = self._create_logging_manager()
        except Exception as e:
            self.logging_manager = None
            self.logger.error(
                f"{LOG_PREFIX} Failed to set up Logging expectations, LOGGING is "
                f"withdrawn and Detection goes on: {e}"
            )
            self._withdraw_logging()
            return
        backend = (
            "Deep Visibility 1.0 (self-hosted)"
            if self.sentinelone_service.client_api.is_self_hosted
            else "SDL v2 (SaaS)"
        )
        self.logger.info(
            f"{LOG_PREFIX} Logging expectations enabled: search backend {backend}, "
            f"max interval {self.config_instance.sentinelone.logging_max_interval}"
        )

    def _create_logging_manager(self) -> LoggingManager:
        """Create the Logging manager on the event search of SentinelOne.

        The event search is the one Detection uses for its SHA1 lookup: SDL
        on SaaS, Deep Visibility on self-hosted.

        Returns:
            The Logging manager.

        """
        client_api = self.sentinelone_service.client_api
        self_hosted = client_api.is_self_hosted
        fetcher = self.sentinelone_service.deep_visibility_fetcher
        return LoggingManager(
            oaev_api=self.api,
            collector_id=self.get_id(),
            build_query=lambda expectation: build_logging_query(
                _signature_dicts(expectation), self_hosted
            ),
            fetch_events=lambda query: fetch_logging_events(fetcher, query),
            build_trace=lambda match, query, expectation_id, collector_id: (
                build_logging_trace(
                    match,
                    query,
                    expectation_id,
                    collector_id,
                    client_api.base_url,
                    self_hosted,
                )
            ),
            period=self.config_instance.collector.period,  # type: ignore[arg-type]
            max_interval=self.config_instance.sentinelone.logging_max_interval,
            on_suspend=self._withdraw_logging,
        )

    def _withdraw_logging(self) -> None:
        """Stop declaring LOGGING, so the platform stops waiting for its results."""
        self.update_supported_expectation_types(list(ALERT_EXPECTATION_TYPES))

    def _run_logging_pass(self) -> None:
        """Run the Logging pass, which must never stop the Detection pass."""
        if getattr(self, "logging_manager", None) is None:
            return
        try:
            summary = self.logging_manager.process()
            stopped = ""
            if summary.suspended:
                stopped = ", suspended"
            elif summary.rate_limited:
                stopped = ", stopped by the rate limit"
            self.logger.info(
                f"{LOG_PREFIX} Logging pass completed: {summary.fetched} fetched, "
                f"{summary.logged} logged, {summary.deferred} deferred, "
                f"{summary.over_budget} over budget, "
                f"{summary.skipped_no_end_date} without end date, "
                f"{summary.unqueryable} unqueryable, {summary.no_match} no match, "
                f"{summary.errors} errors{stopped}"
            )
        except Exception as e:  # never block Detection
            self.logger.error(f"{LOG_PREFIX} Logging pass failed: {e}")
