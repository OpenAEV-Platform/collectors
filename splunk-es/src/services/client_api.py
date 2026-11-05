"""Splunk ES API client for making HTTP requests with proper error handling."""

import fnmatch
import logging
import string
import time
from datetime import timedelta
from typing import Any

import requests  # type: ignore[import-untyped]
from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError,
    RequestException,
    Timeout,
)

from ..models.configs.config_loader import ConfigLoader
from .exception import (
    SplunkESAPIError,
    SplunkESAuthenticationError,
    SplunkESNetworkError,
    SplunkESQueryError,
    SplunkESSessionError,
    SplunkESValidationError,
)
from .logging_fetch import (
    LoggingApiError,
    LoggingAuthError,
    LoggingEmpty,
    LoggingFetchResult,
    LoggingIndexCheck,
    LoggingIndexCheckResult,
    LoggingMalformed,
    LoggingRows,
    parse_logging_rows,
)
from .logging_query import LoggingQuery
from .models import SplunkESAlert, SplunkESResponse, SplunkESSearchCriteria
from .utils.epoch import to_epoch

LOG_PREFIX = "[SplunkESClientAPI]"


DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3

DEFAULT_QUERY_TEMPLATE = (
    "index={alerts_index} "
    "(src_ip IN ({source_ips}) OR src IN ({source_ips}) OR source_ip IN ({source_ips}) OR client_ip IN ({source_ips})) "
    "(dst_ip IN ({target_ips}) OR dest IN ({target_ips}) OR dest_ip IN ({target_ips}) "
    "OR destination_ip IN ({target_ips}) OR server_ip IN ({target_ips})) "
    "(host IN ({hostnames}) OR hostname IN ({hostnames}) OR host_name IN ({hostnames})) "
    "earliest={start_date} latest={end_date} "
    "| table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, "
    "destination_ip, server_ip, host, hostname, signature, rule_name, event_type, "
    "severity, url_path, _raw | sort -_time"
)

ALLOWED_PLACEHOLDERS = {
    "alerts_index",
    "source_ips",
    "target_ips",
    "hostnames",
    "start_date",
    "end_date",
}

# Defaults the OpenAEV catalog used to prefill, stored as-is on deployed
# instances. Their {process_conditions} / {implant_urls} / {implant_names}
# placeholders were dropped in #489 (implant matching moved to the regex
# engine), so they would now fail validation: run the built-in query instead.
LEGACY_DEFAULT_QUERY_TEMPLATES = (
    "index={alerts_index} "
    "(src_ip IN ({source_ips}) OR src IN ({source_ips}) OR source_ip IN ({source_ips}) OR client_ip IN ({source_ips})) "
    "(dst_ip IN ({target_ips}) OR dest IN ({target_ips}) OR dest_ip IN ({target_ips}) "
    "OR destination_ip IN ({target_ips}) OR server_ip IN ({target_ips})) "
    "{process_conditions} earliest={start_date} latest={end_date} "
    "| table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, "
    "destination_ip, server_ip, signature, rule_name, event_type, severity, "
    "url_path, url, path, query, _raw | sort -_time",
    "index={alerts_index} "
    "(src_ip IN ({source_ips}) OR src IN ({source_ips}) OR source_ip IN ({source_ips}) OR client_ip IN ({source_ips})) "
    "(dst_ip IN ({target_ips}) OR dest IN ({target_ips}) OR dest_ip IN ({target_ips}) "
    "OR destination_ip IN ({target_ips}) OR server_ip IN ({target_ips})) "
    "(url_path IN ({implant_urls}) OR url IN ({implant_urls}) OR path IN ({implant_urls}) "
    "OR query IN ({implant_urls}) OR process_name IN ({implant_names}) "
    "OR parent_process_name IN ({implant_names})) "
    "earliest={start_date} latest={end_date} "
    "| table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, "
    "destination_ip, server_ip, signature, rule_name, event_type, severity, "
    "url_path, url, path, query, process_name, parent_process_name, _raw | sort -_time",
)


class _SafeFormatter(string.Formatter):
    """Restricted formatter that prevents attribute/index access in format strings."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> tuple:
        """Override to block attribute traversal (e.g., {value.__class__})."""
        if "." in field_name or "[" in field_name:
            raise ValueError(
                f"Attribute/index access not allowed in query template: '{field_name}'"
            )
        return super().get_field(field_name, args, kwargs)


_safe_formatter = _SafeFormatter()


def _normalize_whitespace(template: str) -> str:
    """Collapse whitespace runs so a reflowed template compares equal."""
    return " ".join(template.split())


class SplunkESClientAPI:
    """Splunk ES API client for fetching alerts and data."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the Splunk ES API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            SplunkESValidationError: If config is None or has invalid structure.
            SplunkESSessionError: If session creation fails.

        """
        if config is None:
            raise SplunkESValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.splunk_es.base_url).rstrip("/")
            self.username = self.config.splunk_es.username
            self.password = self.config.splunk_es.password.get_secret_value()
            self.alerts_index = self.config.splunk_es.alerts_index or "_notable"
            self.offset = self.config.splunk_es.offset.total_seconds()
            self.max_retry = self.config.splunk_es.max_retry
        except AttributeError as e:
            raise SplunkESValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.splunk_es, "time_window")
            and self.config.splunk_es.time_window
        ):
            self.time_window = self.config.splunk_es.time_window
        else:
            self.time_window = timedelta(hours=DEFAULT_TIME_WINDOW_HOURS)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default {DEFAULT_TIME_WINDOW_HOURS} hour"
            )

        self.query_template = self.config.splunk_es.query_template
        if self.query_template and _normalize_whitespace(self.query_template) in {
            _normalize_whitespace(legacy) for legacy in LEGACY_DEFAULT_QUERY_TEMPLATES
        }:
            self.logger.warning(
                f"{LOG_PREFIX} The configured query template is a former built-in "
                "default this version no longer supports: using the current "
                "built-in default query template instead"
            )
            self.query_template = DEFAULT_QUERY_TEMPLATE
        elif self.query_template:
            self._validate_template_placeholders(self.query_template)
            if _normalize_whitespace(self.query_template) == _normalize_whitespace(
                DEFAULT_QUERY_TEMPLATE
            ):
                # The catalog prefills the built-in query: report it as such.
                self.logger.info(
                    f"{LOG_PREFIX} Using the built-in default query template"
                )
            else:
                self.logger.info(
                    f"{LOG_PREFIX} Using a custom query template from configuration"
                )
        else:
            self.query_template = DEFAULT_QUERY_TEMPLATE
            self.logger.info(
                f"{LOG_PREFIX} No query template configured, using the built-in "
                "default query template"
            )

        try:
            self.session = self._create_session()
        except Exception as e:
            raise SplunkESSessionError(f"Failed to create HTTP session: {e}") from e

        self.logger.info(f"{LOG_PREFIX} Splunk ES API client initialized successfully")

    def _validate_template_placeholders(self, template: str) -> None:
        """Validate that a custom query template only uses allowed placeholders.

        Args:
            template: The query template string to validate.

        Raises:
            SplunkESValidationError: If unknown placeholders are found.

        """
        formatter = string.Formatter()
        used_placeholders = {
            field_name
            for _, field_name, _, _ in formatter.parse(template)
            if field_name is not None
        }
        unknown = used_placeholders - ALLOWED_PLACEHOLDERS
        if unknown:
            raise SplunkESValidationError(
                f"Unknown placeholders in query template: {unknown}. "
                f"Allowed: {sorted(ALLOWED_PLACEHOLDERS)}"
            )

    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper authentication.

        Returns:
            Configured requests.Session with authentication.

        Raises:
            SplunkESValidationError: If credentials are missing.
            SplunkESSessionError: If session configuration fails.

        """
        if not self.username or not self.password:
            raise SplunkESValidationError(
                "Username and password are required for session creation"
            )

        try:
            session = requests.Session()
            session.auth = (self.username, self.password)
            session.headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                }
            )
            session.timeout = REQUEST_TIMEOUT_SECONDS
            session.verify = False
            return session
        except Exception as e:
            raise SplunkESSessionError(f"Failed to configure session: {e}") from e

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[SplunkESAlert]:
        """Fetch Splunk ES alerts based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If inputs are invalid.
            SplunkESAPIError: If API operations fail.

        """
        if not search_signatures:
            raise SplunkESValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise SplunkESValidationError(
                f"Invalid expectation_type: {expectation_type}. Splunk ES only supports 'detection'"
            )

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching signatures for {expectation_type} expectation with {len(search_signatures)} signatures"
            )

            search_criteria = self._build_search_criteria(search_signatures)

            self.logger.debug(f"{LOG_PREFIX} Executing Splunk ES query with retry...")
            alerts = self._execute_splunk_query_with_retry(search_criteria)

            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(alerts)} alerts from Splunk ES"
            )
            return alerts

        except SplunkESValidationError, SplunkESAPIError, SplunkESAuthenticationError:
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SplunkESAPIError(f"Unexpected error fetching signatures: {e}") from e

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> SplunkESSearchCriteria:
        """Build SplunkESSearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            SplunkESSearchCriteria object.

        Raises:
            SplunkESValidationError: If signature format is invalid.

        """
        try:
            self.logger.debug(
                f"{LOG_PREFIX} Building search criteria from {len(search_signatures)} signatures"
            )

            source_ips = []
            target_ips = []
            host_names = []
            start_date = None
            end_date = None

            # String-keyed mapping (never attribute-accessing the enum) keeps
            # this robust across pyoaev versions.
            host_mapping = {
                "hostname": host_names,
                "target_hostname_address": host_names,
            }

            for sig in search_signatures:
                if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                    raise SplunkESValidationError(f"Invalid signature format: {sig}")

                sig_type = sig.get("type")
                sig_value = sig.get("value")
                self.logger.debug(
                    f"{LOG_PREFIX} Processing signature: {sig_type}={sig_value}"
                )

                if sig_type in ("source_ipv4_address", "source_ipv6_address"):
                    source_ips.append(sig_value)
                elif sig_type in ("target_ipv4_address", "target_ipv6_address"):
                    target_ips.append(sig_value)
                elif sig_type in host_mapping:
                    host_mapping[sig_type].append(sig_value)
                elif sig_type == "start_date":
                    start_date = sig_value
                elif sig_type == "end_date":
                    end_date = sig_value
                else:
                    # The query carries only an "enough filter": all other
                    # signature types are carried by the matcher only.
                    self.logger.debug(
                        f"{LOG_PREFIX} Signature type '{sig_type}' is carried by the matcher only, not by the query"
                    )

            if not start_date and not end_date:
                self.logger.info(
                    f"{LOG_PREFIX} No date signatures provided, will use time_window in query: {self.time_window}"
                )

            criteria = SplunkESSearchCriteria(
                source_ips=source_ips,
                target_ips=target_ips,
                hostnames=host_names,
                start_date=start_date,
                end_date=end_date,
            )

            self.logger.debug(
                f"{LOG_PREFIX} Built search criteria: source_ips={len(source_ips)}, target_ips={len(target_ips)}, "
                f"hostnames={len(host_names)}, date_range={start_date} to {end_date}"
            )
            return criteria

        except SplunkESValidationError:
            raise
        except Exception as e:
            raise SplunkESValidationError(
                f"Failed to build search criteria: {e}"
            ) from e

    def _execute_splunk_query(
        self, search_criteria: SplunkESSearchCriteria, extend_end_seconds: int = 0
    ) -> list[SplunkESAlert]:
        """Execute Splunk ES query based on search criteria.

        Args:
            search_criteria: SplunkESSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If search criteria is invalid.
            SplunkESQueryError: If query execution fails.
            SplunkESAuthenticationError: If authentication fails.
            SplunkESAPIError: If API call fails.

        """
        if not search_criteria:
            raise SplunkESValidationError("search_criteria cannot be None")

        try:
            spl_query = self._build_spl_query(search_criteria, extend_end_seconds)

            self.logger.debug(f"{LOG_PREFIX} Executing SPL query: {spl_query}")

            response = self._post_oneshot_search(f"search {spl_query}", count="0")

            if response.status_code == 401:
                raise SplunkESAuthenticationError(
                    "Authentication with Splunk ES failed"
                )
            elif response.status_code != 200:
                raise SplunkESAPIError(
                    f"Splunk ES API returned status {response.status_code}: {response.text}"
                )

            response_data = response.json()
            splunk_response = SplunkESResponse.from_raw_response(response_data)

            self.logger.info(
                f"{LOG_PREFIX} Retrieved {len(splunk_response.results)} alerts from Splunk ES"
            )
            return splunk_response.results

        except (
            SplunkESValidationError,
            SplunkESQueryError,
            SplunkESAuthenticationError,
            SplunkESAPIError,
        ):
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during query: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed during query: {e}") from e
        except Exception as e:
            raise SplunkESQueryError(f"Unexpected error executing query: {e}") from e

    def _post_oneshot_search(self, search: str, count: str) -> requests.Response:
        """Run one blocking (oneshot) Splunk search and return the raw response.

        Args:
            search: The full search, starting with ``search``.
            count: Maximum number of results, ``"0"`` for no limit.

        Returns:
            The HTTP response; the caller checks its status.

        """
        endpoint = f"{self.base_url}/services/search/jobs"
        params = {
            "search": search,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": count,
        }
        return self.session.post(endpoint, data=params, timeout=REQUEST_TIMEOUT_SECONDS)

    def fetch_logging_events(self, query: LoggingQuery) -> LoggingFetchResult:
        """Run the Logging search of one expectation, once.

        There is no retry and no sleep: an expectation without events is
        searched again on a later collector cycle. Expected Splunk errors are
        returned, not raised, and an error is never reported as "no event".

        Args:
            query: The Logging search built by ``build_logging_query``.

        Returns:
            ``LoggingRows`` with the events, ``LoggingEmpty`` when the search
            found nothing, ``LoggingAuthError`` on HTTP 401 / 403,
            ``LoggingApiError`` on another HTTP error, a timeout or a network
            error, ``LoggingMalformed`` when the answer is not the expected
            JSON.

        """
        self.logger.debug(f"{LOG_PREFIX} Executing Logging search: {query.spl}")
        results = self._run_logging_search(query.spl, count="0")
        if not isinstance(results, list):
            return results
        if not results:
            return LoggingEmpty()

        events, skipped = parse_logging_rows(results)
        if not events:
            return LoggingMalformed(
                message=f"None of the {len(results)} rows could be read"
            )
        if skipped:
            self.logger.debug(
                f"{LOG_PREFIX} Skipped {skipped} malformed Logging rows "
                f"out of {len(results)}"
            )
        return LoggingRows(events=events, skipped=skipped)

    def check_logging_indexes(self, logging_indexes: str) -> LoggingIndexCheckResult:
        """Check that the Logging indexes exist and can be read.

        Splunk silently returns no event for an index that does not exist or
        that the role cannot read. A typo in ``SPLUNKES_LOGGING_INDEXES``
        would then look like "nothing was logged" and every LOGGING
        expectation would expire as "Not Logged". ``eventcount`` lists only
        the indexes the role can read, empty ones included, so an index
        missing from its answer is a typo or a missing permission.

        Args:
            logging_indexes: ``SPLUNKES_LOGGING_INDEXES``, comma-separated
                index names, ``*`` wildcards allowed.

        Returns:
            ``LoggingIndexCheck`` with the found and missing indexes (a
            wildcard is found when it matches at least one index), or the
            error state of the search.

        """
        indexes = [name.strip() for name in logging_indexes.split(",") if name.strip()]
        search = "| eventcount summarize=false {} | dedup index | table index".format(
            " ".join(f"index={index}" for index in indexes)
        )
        results = self._run_logging_search(search, count="0")
        if not isinstance(results, list):
            return results

        # A row without an index name means an unexpected answer: report it
        # as such, never as missing indexes.
        if not all(
            isinstance(row, dict)
            and isinstance(row.get("index"), str)
            and row.get("index")
            for row in results
        ):
            return LoggingMalformed(message="eventcount rows without an index name")
        readable = {row["index"].lower() for row in results}
        found = [
            index
            for index in indexes
            if any(fnmatch.fnmatchcase(name, index.lower()) for name in readable)
        ]
        missing = [index for index in indexes if index not in found]
        if missing:
            self.logger.error(
                f"{LOG_PREFIX} Logging indexes not found or not readable by the "
                f"Splunk role: {', '.join(missing)}. Searches on them return no "
                "event, so LOGGING expectations would expire as Not Logged"
            )
        return LoggingIndexCheck(found=found, missing=missing)

    def _run_logging_search(
        self, search: str, count: str
    ) -> list[Any] | LoggingAuthError | LoggingApiError | LoggingMalformed:
        """Run one Logging oneshot search and return its rows or its error.

        Args:
            search: The full search.
            count: Maximum number of results, ``"0"`` for no limit.

        Returns:
            The ``results`` rows, or ``LoggingAuthError`` on HTTP 401 / 403,
            ``LoggingApiError`` on another HTTP error, a timeout, a network
            error or a search error reported in ``messages``,
            ``LoggingMalformed`` when the answer is not the expected JSON.

        """
        try:
            response = self._post_oneshot_search(search, count=count)
        except RequestException as e:
            # Timeout and ConnectionError are RequestException too.
            self.logger.warning(f"{LOG_PREFIX} Logging search failed: {e}")
            return LoggingApiError(message=f"Request failed: {e}")

        if response.status_code in (401, 403):
            self.logger.warning(
                f"{LOG_PREFIX} Logging search refused by Splunk "
                f"(HTTP {response.status_code}): check the credentials and the "
                "role's access to the Logging indexes"
            )
            return LoggingAuthError(
                status_code=response.status_code,
                message=_short_text(response.text),
            )
        if response.status_code != 200:
            self.logger.warning(
                f"{LOG_PREFIX} Logging search failed with HTTP {response.status_code}"
            )
            return LoggingApiError(
                message=_short_text(response.text),
                status_code=response.status_code,
            )

        try:
            data = response.json()
        except ValueError as e:
            return LoggingMalformed(message=f"Response is not JSON: {e}")
        if not isinstance(data, dict):
            return LoggingMalformed(message="Response is not a JSON object")

        # A broken search (bad SPL, bad time bound) still answers HTTP 200 with
        # no rows: the error is only in "messages". Without this check it
        # would look like "no event found" and expire as Not Logged.
        search_error = _search_error_text(data.get("messages"))
        if search_error:
            self.logger.error(
                f"{LOG_PREFIX} Splunk rejected the Logging search: {search_error}"
            )
            return LoggingApiError(message=search_error, status_code=200)

        results = data.get("results")
        if not isinstance(results, list):
            return LoggingMalformed(message="Response has no 'results' list")
        return results

    def _execute_splunk_query_with_retry(
        self, search_criteria: SplunkESSearchCriteria
    ) -> list[SplunkESAlert]:
        """Execute Splunk ES query with retry mechanism.

        Args:
            search_criteria: SplunkESSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If search criteria is invalid.
            SplunkESQueryError: If query execution fails after all retries.
            SplunkESAuthenticationError: If authentication fails.
            SplunkESAPIError: If API call fails after all retries.

        """
        if not search_criteria:
            raise SplunkESValidationError("search_criteria cannot be None")

        self.logger.info(
            f"{LOG_PREFIX} Starting Splunk ES fetch with {self.offset}s offset and {self.max_retry} max retries"
        )

        last_exception = None

        for attempt in range(self.max_retry + 1):
            try:
                self.logger.debug(
                    f"{LOG_PREFIX} Splunk ES query attempt {attempt + 1} of {self.max_retry + 1}"
                )

                if attempt > 0:
                    sleep_time = int(self.offset)
                    self.logger.debug(
                        f"{LOG_PREFIX} Waiting {sleep_time}s before retry {attempt + 1}..."
                    )
                    time.sleep(sleep_time)
                    extend_seconds = sleep_time * attempt
                else:
                    extend_seconds = 0

                alerts = self._execute_splunk_query(search_criteria, extend_seconds)

                if alerts:
                    self.logger.info(
                        f"{LOG_PREFIX} Splunk ES attempt {attempt + 1}: Found {len(alerts)} alerts - success!"
                    )
                    return alerts
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} Splunk ES attempt {attempt + 1}: No alerts found"
                    )
                    if attempt == self.max_retry:
                        self.logger.warning(
                            f"{LOG_PREFIX} No alerts found after all retry attempts"
                        )
                        return []

            except (SplunkESAuthenticationError, SplunkESValidationError) as e:
                raise e
            except (
                SplunkESAPIError,
                SplunkESNetworkError,
                SplunkESQueryError,
                ConnectionError,
                Timeout,
                RequestException,
            ) as e:
                last_exception = e
                self.logger.warning(
                    f"{LOG_PREFIX} Splunk ES attempt {attempt + 1} failed: {e}"
                )
                if attempt == self.max_retry:
                    break

        if last_exception:
            raise SplunkESAPIError(
                f"All Splunk ES fetch attempts failed. Last error: {last_exception}"
            ) from last_exception
        else:
            self.logger.warning(
                f"{LOG_PREFIX} No alerts found after all retry attempts"
            )
            return []

    def fetch_with_retry(
        self,
        search_signatures: list[dict[str, Any]],
        expectation_type: str,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[SplunkESAlert]:
        """Fetch Splunk ES alerts with retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If inputs are invalid.
            SplunkESAPIError: If all retry attempts fail.

        """
        if not search_signatures:
            raise SplunkESValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise SplunkESValidationError(
                f"Invalid expectation_type: {expectation_type}. Splunk ES only supports 'detection'"
            )

        if max_retries is None:
            max_retries = self.max_retry
        if offset_seconds is None:
            offset_seconds = int(self.offset)

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting fetch with retry: max_retries={max_retries}, offset={offset_seconds}s"
            )

            search_criteria = self._build_search_criteria(search_signatures)

            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    self.logger.debug(
                        f"{LOG_PREFIX} Fetch attempt {attempt + 1} of {max_retries + 1}"
                    )

                    if attempt > 0:
                        self.logger.debug(
                            f"{LOG_PREFIX} Waiting {offset_seconds}s before retry {attempt + 1}..."
                        )
                        time.sleep(offset_seconds)
                        extend_seconds = offset_seconds * attempt
                    else:
                        extend_seconds = 0

                    alerts = self._execute_splunk_query(search_criteria, extend_seconds)

                    if alerts:
                        self.logger.info(
                            f"{LOG_PREFIX} Fetch attempt {attempt + 1}: Found {len(alerts)} alerts - success!"
                        )
                        return alerts
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Fetch attempt {attempt + 1}: No alerts found"
                        )

                except (SplunkESAuthenticationError, SplunkESValidationError) as e:
                    raise e
                except (
                    SplunkESAPIError,
                    SplunkESNetworkError,
                    SplunkESQueryError,
                    ConnectionError,
                    Timeout,
                    RequestException,
                ) as e:
                    last_exception = e
                    self.logger.warning(
                        f"{LOG_PREFIX} Fetch attempt {attempt + 1} failed: {e}"
                    )

            if last_exception:
                raise SplunkESAPIError(
                    f"All fetch attempts failed. Last error: {last_exception}"
                ) from last_exception
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No alerts found after all retry attempts"
                )
                return []

        except SplunkESValidationError, SplunkESAPIError, SplunkESAuthenticationError:
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SplunkESAPIError(f"Unexpected error in fetch_with_retry: {e}") from e

    def _build_spl_query(
        self, search_criteria: SplunkESSearchCriteria, extend_end_seconds: int = 0
    ) -> str:
        """Build SPL query from search criteria.

        If a custom query template is configured, resolves placeholders in it.
        Otherwise, uses the built-in query construction logic.

        Args:
            search_criteria: SplunkESSearchCriteria object.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            SPL query string.

        Raises:
            SplunkESValidationError: If criteria is invalid.

        """
        try:
            source_ips_str = self._build_ip_list(search_criteria.source_ips)
            target_ips_str = self._build_ip_list(search_criteria.target_ips)
            hostnames_str = self._build_ip_list(search_criteria.hostnames or [])
            time_window_seconds = int(self.time_window.total_seconds())
            earliest_seconds = time_window_seconds + extend_end_seconds

            # Resolve start_date/end_date. Splunk's earliest/latest modifiers do
            # NOT parse ISO-8601 timestamps with a 'Z' suffix (as sent in OpenAEV
            # expectation signatures, e.g. 2026-09-11T08:02:10.806778868Z), which
            # silently breaks the time bounds and returns 0 results. Convert them
            # to epoch. Extend the latest bound on retries to widen the window.
            start_epoch = to_epoch(search_criteria.start_date)
            start_date_str = (
                str(start_epoch) if start_epoch is not None else f"-{earliest_seconds}s"
            )
            end_epoch = to_epoch(search_criteria.end_date)
            end_date_str = (
                str(end_epoch + extend_end_seconds) if end_epoch is not None else "now"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Using time range: earliest={start_date_str}, latest={end_date_str} "
                f"(base: {time_window_seconds}s + extend: {extend_end_seconds}s)"
            )

            full_query = _safe_formatter.format(
                self.query_template,
                alerts_index=self.alerts_index or "*",
                source_ips=source_ips_str,
                target_ips=target_ips_str,
                hostnames=hostnames_str,
                start_date=start_date_str,
                end_date=end_date_str,
            )

            # Normalize whitespace: collapse runs of spaces caused by empty placeholders.
            # This is safe because SPL tokens are never whitespace-sensitive.
            full_query = " ".join(full_query.split())

            if "| table" not in full_query:
                self.logger.error(
                    f"{LOG_PREFIX} Query template does not contain '| table' pipe. "
                    "Alert parsing will fail without proper field extraction."
                )

            self.logger.debug(f"{LOG_PREFIX} Built SPL query: {full_query}")
            return full_query

        except (KeyError, ValueError) as e:
            raise SplunkESValidationError(f"Invalid query template: {e}") from e
        except Exception as e:
            raise SplunkESValidationError(f"Failed to build SPL query: {e}") from e

    @staticmethod
    def _build_ip_list(ips: list[str]) -> str:
        """Build a quoted comma-separated value list for Splunk IN operator.

        Values (IP addresses or hostnames) are wrapped in double quotes for
        SPL; embedded double quotes are backslash-escaped so freer-form
        values such as attacker-influenced hostnames cannot break out of
        the string literal (SPL quote injection).

        Args:
            ips: List of values to quote.

        Returns:
            Quoted CSV string for Splunk IN(), or "*" if empty.

        """
        if not ips:
            return "*"
        return ",".join(f'"{ip.replace(chr(34), chr(92) + chr(34))}"' for ip in ips)


def _short_text(text: str, limit: int = 200) -> str:
    """Shorten a Splunk error body so it can be logged or carried safely."""
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit] + "..."


def _search_error_text(messages: Any) -> str | None:
    """Return the text of the first FATAL or ERROR message of a search answer.

    INFO and WARN messages (e.g. "Your timerange was substituted") are normal
    and ignored.

    Args:
        messages: The ``messages`` list of the Splunk JSON answer.

    Returns:
        The shortened error text, or None when there is no error message.

    """
    if not isinstance(messages, list):
        return None
    for message in messages:
        if not isinstance(message, dict):
            continue
        if str(message.get("type", "")).upper() in ("FATAL", "ERROR"):
            return _short_text(message.get("text") or "Unknown Splunk search error")
    return None
