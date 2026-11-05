"""Core collector."""

import os
from typing import assert_never

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    LoggingExpectation,
)
from pyoaev.daemons import CollectorDaemon  # type: ignore[import-untyped]
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from src.services.expectation_service import SplunkESExpectationService
from src.services.logging_fetch import (
    LoggingApiError,
    LoggingAuthError,
    LoggingIndexCheck,
    LoggingMalformed,
)
from src.services.logging_query import build_logging_query
from src.services.logging_trace import LoggingTraceBuilder
from src.services.trace_service import SplunkESTraceService
from src.services.utils import SplunkESConfig

from .exception import (
    CollectorConfigError,
    CollectorProcessingError,
    CollectorSetupError,
)
from .expectation_handler import GenericExpectationHandler
from .expectation_manager import GenericExpectationManager
from .logging_manager import LoggingManager

LOG_PREFIX = "[Collector]"
COLLECTOR_TYPE = "openaev_splunk_es"
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
            self.config = SplunkESConfig()
            self.config_instance = self.config.load
            # "is True": a mocked config must not turn Logging on.
            self.logging_enabled = (
                self.config_instance.splunk_es.logging_enabled is True
            )

            super().__init__(
                configuration=self.config_instance.to_daemon_config(),
                callback=self._process_callback,
                collector_type=COLLECTOR_TYPE,
                supported_expectation_types=self._declared_expectation_types(),
            )
            self.logging_manager: LoggingManager | None = None

            self.logger.info(  # type: ignore[has-type]
                f"{LOG_PREFIX} Splunk Enterprise Security Collector initialized successfully"
            )

        except Exception as err:
            import logging

            logging.basicConfig(level=logging.ERROR)
            self.logger = logging.getLogger(__name__)
            self.logger.error(f"{LOG_PREFIX} Failed to initialize collector: {err}")
            raise CollectorConfigError(
                f"Failed to initialize the collector: {err}"
            ) from err

    def _setup(self) -> None:
        """Set up the collector.

        Initializes Splunk Enterprise Security services, expectation handler, expectation manager,
        and OpenAEV detection helper. Sets up the collector for processing expectations.

        Raises:
            CollectorSetupError: If collector setup fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting collector setup...")

            super()._setup()

            self.logger.debug(
                f"{LOG_PREFIX} Initializing Splunk Enterprise Security services..."
            )

            self.splunkes_service = SplunkESExpectationService(self.config_instance)

            self.trace_service = SplunkESTraceService(
                self.config_instance, client_api=self.splunkes_service.client_api
            )

            self.expectation_handler = GenericExpectationHandler(self.splunkes_service)

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

            supported_signatures = self.splunkes_service.get_supported_signatures()
            self.oaev_detection_helper = OpenAEVDetectionHelper(
                logger=self.logger,
                relevant_signatures_types=supported_signatures,
            )

            self.logger.info(f"{LOG_PREFIX} Collector setup completed successfully")
            self.logger.info(
                f"{LOG_PREFIX} Supported signatures: {[sig.value for sig in supported_signatures]}"
            )

            service_info = self.splunkes_service.get_service_info()
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
            self._run_logging_pass()

            self.logger.debug(
                f"{LOG_PREFIX} Processing expectations using SplunkES services"
            )

            results = self.expectation_manager.process_expectations(
                detection_helper=self.oaev_detection_helper
            )

            self.logger.info(
                f"{LOG_PREFIX} Processing cycle completed: {results.processed} total, "
                f"{results.valid} valid, {results.invalid} invalid, "
                f"{results.skipped} skipped"
            )

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
            indexes = self.config_instance.splunk_es.logging_indexes or ""
        except Exception as e:
            self.logging_manager = None
            self.logger.error(
                f"{LOG_PREFIX} Failed to set up Logging expectations, LOGGING is "
                f"withdrawn and Detection goes on: {e}"
            )
            self._withdraw_logging()
            return
        if not self._logging_indexes_searchable(indexes):
            self.logging_manager = None
            self._withdraw_logging()
            return
        self.logger.info(
            f"{LOG_PREFIX} Logging expectations enabled on "
            f"{len([name for name in indexes.split(',') if name.strip()])} indexes"
        )

    def _logging_indexes_searchable(self, indexes: str) -> bool:
        """Check once that Splunk can search at least one Logging index.

        Splunk returns no event for an index that does not exist or that the
        role cannot read: without this check, every LOGGING expectation would
        expire as "Not Logged". A check that cannot run (Splunk down, odd
        answer) does not stop Logging: the searches run and report their own
        errors.

        Args:
            indexes: SPLUNKES_LOGGING_INDEXES as configured.

        Returns:
            False when Splunk refuses the check or none of the indexes can be
            searched, True otherwise.

        """
        withdrawn = "LOGGING is withdrawn and Detection goes on"
        try:
            check = self.splunkes_service.client_api.check_logging_indexes(indexes)
            if isinstance(check, LoggingAuthError):
                answer = f"HTTP {check.status_code}"
                if check.message:
                    answer += f": {check.message}"
                self.logger.error(
                    f"{LOG_PREFIX} Splunk refused the Logging index check "
                    f"({answer}). Check that the Splunk account can search the "
                    f"Logging indexes, then restart the collector. {withdrawn}"
                )
                return False
            if isinstance(check, LoggingIndexCheck):
                if check.found:
                    return True
                self.logger.error(
                    f"{LOG_PREFIX} None of the {len(check.missing)} Logging indexes "
                    f"can be searched (SPLUNKES_LOGGING_INDEXES). {withdrawn}"
                )
                return False
            if not isinstance(check, (LoggingApiError, LoggingMalformed)):
                assert_never(check)
            reason = f"{type(check).__name__}: {check.message}"
        except Exception as e:
            reason = str(e)
        self.logger.warning(
            f"{LOG_PREFIX} Could not check the Logging indexes ({reason}), "
            "Logging goes on"
        )
        return True

    def _create_logging_manager(self) -> LoggingManager:
        """Create the Logging manager on the Logging search of Splunk.

        Returns:
            The Logging manager.

        """
        splunk_es = self.config_instance.splunk_es
        # Read now, not in each search: a wrong setting name fails the setup,
        # which withdraws LOGGING, instead of failing every search.
        indexes = splunk_es.logging_indexes
        template = splunk_es.logging_query_template
        return LoggingManager(
            oaev_api=self.api,
            collector_id=self.get_id(),
            build_query=lambda expectation: build_logging_query(
                _signature_dicts(expectation), indexes, template
            ),
            fetch_events=self.splunkes_service.client_api.fetch_logging_events,
            trace_builder=LoggingTraceBuilder(self.config_instance),
            period=self.config_instance.collector.period,  # type: ignore[arg-type]
            max_interval=splunk_es.logging_max_interval,
            on_suspend=self._withdraw_logging,
        )

    def _withdraw_logging(self) -> None:
        """Stop declaring LOGGING, so the platform stops waiting for its results."""
        self.update_supported_expectation_types(list(ALERT_EXPECTATION_TYPES))

    def _run_logging_pass(self) -> None:
        """Run the Logging pass, which must never stop the Detection pass."""
        if self.logging_manager is None:
            return
        try:
            summary = self.logging_manager.process()
            suspended = ", suspended" if summary.suspended else ""
            self.logger.info(
                f"{LOG_PREFIX} Logging pass completed: {summary.fetched} fetched, "
                f"{summary.logged} logged, {summary.deferred} deferred, "
                f"{summary.over_budget} over budget, "
                f"{summary.skipped_no_end_date} without end date, "
                f"{summary.unqueryable} unqueryable, {summary.no_match} no match, "
                f"{summary.errors} errors{suspended}"
            )
        except Exception as e:  # never block Detection
            self.logger.error(f"{LOG_PREFIX} Logging pass failed: {e}")
