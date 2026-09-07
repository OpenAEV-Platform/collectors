"""SentinelOne SDL v2 deep-search fetcher for SaaS instances."""

import logging
import time
from datetime import datetime, timezone
from typing import Any

from requests import ConnectionError, RequestException, Timeout

from .client_api import SentinelOneClientAPI
from .exception import (
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneValidationError,
)

LOG_PREFIX = "[FetcherSDL]"
REQUEST_TIMEOUT_SECONDS = 30
PAGE_LIMIT = 100
MAX_PAGES = 200
MAX_POLL_ATTEMPTS = 30
POLL_INTERVAL_SECONDS = 2
MAX_RATE_LIMIT_RETRIES = 4
FORWARD_TAG_HEADER = "x-dataset-query-forward-tag"
S1QL_BASE_FILTER = "dataSource.name='SentinelOne' dataSource.category='security'"


class FetcherSDL:
    """Fetcher for SentinelOne SDL v2 deep-search (SaaS) events by file SHA1."""

    def __init__(self, client_api: SentinelOneClientAPI):
        """Initialize the SDL v2 fetcher.

        Args:
            client_api: SentinelOne API client instance.

        """
        self.client_api = client_api
        self.logger = logging.getLogger(__name__)

    def fetch_events_for_sha1(
        self, sha1: str, start_time: datetime = None, end_time: datetime = None
    ) -> list[dict[str, Any]]:
        """Fetch SDL v2 deep-search events for a specific SHA1.

        Args:
            sha1: SHA1 hash to search for.
            start_time: Start time for the search (optional).
            end_time: End time for the search (optional).

        Returns:
            List of event dictionaries compatible with threat events.

        Raises:
            SentinelOneValidationError: If SHA1 is invalid.
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        if not sha1 or not isinstance(sha1, str):
            raise SentinelOneValidationError("SHA1 must be a non-empty string")

        try:
            start_time, end_time = self._resolve_time_window(start_time, end_time)
            s1ql_filter = self._build_s1ql_filter([sha1])

            self.logger.debug(f"{LOG_PREFIX} Fetching SDL events for SHA1: {sha1}")
            self.logger.debug(f"{LOG_PREFIX} S1QL filter: {s1ql_filter}")

            rows = self._fetch_all_rows(s1ql_filter, start_time, end_time)

            events = [self._map_row_to_event(row) for row in rows]
            events = [event for event in events if event.get("fileSha1") == sha1]

            self.logger.info(
                f"{LOG_PREFIX} Successfully fetched {len(events)} SDL events for SHA1: {sha1}"
            )
            return events

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error fetching SDL events for SHA1 {sha1}: {e}"
            ) from e

    def fetch_events_for_batch_sha1(
        self,
        sha1_list: list[str],
        start_time: datetime = None,
        end_time: datetime = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Fetch SDL v2 deep-search events for multiple SHA1s in a single query.

        Args:
            sha1_list: List of SHA1 hashes to search for.
            start_time: Start time for the search (optional).
            end_time: End time for the search (optional).

        Returns:
            Dictionary mapping each valid SHA1 to its list of event
            dictionaries. Requested SHA1s with no matches map to an empty
            list; rows whose file SHA1 is not in the requested list are
            dropped.

        Raises:
            SentinelOneValidationError: If SHA1 list is invalid.
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        if not sha1_list or not isinstance(sha1_list, list):
            raise SentinelOneValidationError("sha1_list must be a non-empty list")

        valid_sha1s = [sha1 for sha1 in sha1_list if sha1 and isinstance(sha1, str)]

        if not valid_sha1s:
            self.logger.debug(f"{LOG_PREFIX} No valid SHA1s provided")
            return {}

        try:
            start_time, end_time = self._resolve_time_window(start_time, end_time)
            s1ql_filter = self._build_s1ql_filter(valid_sha1s)

            self.logger.debug(
                f"{LOG_PREFIX} Fetching SDL events for {len(valid_sha1s)} SHA1s in batch"
            )
            self.logger.debug(f"{LOG_PREFIX} S1QL filter: {s1ql_filter}")

            rows = self._fetch_all_rows(s1ql_filter, start_time, end_time)

            sha1_to_events: dict[str, list[dict[str, Any]]] = {
                sha1: [] for sha1 in valid_sha1s
            }

            for row in rows:
                event = self._map_row_to_event(row)
                file_sha1 = event.get("fileSha1")
                if file_sha1 in sha1_to_events:
                    sha1_to_events[file_sha1].append(event)

            total_events = sum(len(events) for events in sha1_to_events.values())
            self.logger.info(
                f"{LOG_PREFIX} Successfully fetched {total_events} total SDL events for {len(valid_sha1s)} SHA1s"
            )
            return sha1_to_events

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error fetching SDL events for batch SHA1s: {e}"
            ) from e

    def _resolve_time_window(
        self, start_time: datetime | None, end_time: datetime | None
    ) -> tuple[datetime, datetime]:
        """Resolve the search window, defaulting to the configured time window.

        Args:
            start_time: Optional explicit start.
            end_time: Optional explicit end.

        Returns:
            Resolved (start_time, end_time) tuple.

        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - self.client_api.time_window
        return start_time, end_time

    def _build_s1ql_filter(self, sha1_list: list[str]) -> str:
        """Build the tenant-wide S1QL 2.0 filter for the given SHA1s.

        The filter is scoped to SentinelOne security events and matches
        tgt.file.sha1 exactly; no 1.0 field names are used.

        Args:
            sha1_list: SHA1 hashes to search for.

        Returns:
            S1QL 2.0 filter expression string.

        """
        escaped = [self._escape_s1ql_string(sha1) for sha1 in sha1_list]
        if len(escaped) == 1:
            return f"{S1QL_BASE_FILTER} tgt.file.sha1='{escaped[0]}'"
        or_expression = " or ".join(f"tgt.file.sha1='{sha1}'" for sha1 in escaped)
        return f"{S1QL_BASE_FILTER} ({or_expression})"

    def _escape_s1ql_string(self, value: str) -> str:
        """Escape a value for embedding in an S1QL single-quoted string.

        Args:
            value: Raw value to escape.

        Returns:
            Value with backslashes escaped before quotes.

        """
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _build_launch_body(
        self,
        s1ql_filter: str,
        start_time: datetime,
        end_time: datetime,
        cursor: str | None,
    ) -> dict:
        """Build the SDL v2 query launch request body.

        Only filter, limit, and cursor are valid log block fields; offset
        and lastCursor are not part of the SDL v2 contract.

        Args:
            s1ql_filter: S1QL 2.0 filter expression.
            start_time: Window start.
            end_time: Window end.
            cursor: Resumption cursor (None on the first page).

        Returns:
            JSON-ready launch body.

        """
        log_block: dict = {"filter": s1ql_filter, "limit": PAGE_LIMIT}
        if cursor:
            log_block["cursor"] = cursor

        return {
            "queryType": "LOG",
            "tenant": True,
            "startTime": self._format_timestamp(start_time),
            "endTime": self._format_timestamp(end_time),
            "queryPriority": "HIGH",
            "log": log_block,
        }

    def _fetch_all_rows(
        self,
        s1ql_filter: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[dict[str, Any]]:
        """Fetch all matching rows by paging the SDL v2 query.

        Page 1 is launched without a cursor; each later page resumes with
        the cursor of the previous page's last row. Resumption is
        inclusive, so rows are deduplicated by cursor (falling back to
        event.id). Paging stops when the first page's estimatedMatchCount
        is reached, when a page yields no new rows, when a short page
        exhausts its estimate, or at the defensive page cap.

        Args:
            s1ql_filter: S1QL 2.0 filter expression.
            start_time: Resolved window start.
            end_time: Resolved window end.

        Returns:
            List of unique raw row dictionaries in fetch order.

        Raises:
            SentinelOneAPIError: If any launch or poll fails.
            SentinelOneNetworkError: If a network error occurs.

        """
        unique_rows: list[dict[str, Any]] = []
        seen_keys: set = set()
        est_total: Any = None
        cursor: str | None = None

        for page_number in range(1, MAX_PAGES + 1):
            body = self._build_launch_body(s1ql_filter, start_time, end_time, cursor)
            query_id, forward_tag = self._launch_query(body)
            final_body = self._poll_query_to_completion(query_id, forward_tag)

            data = self._extract_page_data(final_body)
            page_est = data.get("estimatedMatchCount")
            rows = data.get("matches") or []
            if page_number == 1:
                est_total = page_est

            new_rows = self._collect_new_rows(rows, seen_keys)
            unique_rows.extend(new_rows)

            if self._should_stop_pagination(
                est_total, len(unique_rows), new_rows, rows, page_est
            ):
                break

            cursor = self._next_cursor(rows)
            if cursor is None:
                break
        else:
            self.logger.warning(
                f"{LOG_PREFIX} Reached the maximum of {MAX_PAGES} pages; "
                f"returning {len(unique_rows)} unique rows"
            )

        return unique_rows

    def _collect_new_rows(self, rows: list, seen_keys: set) -> list:
        """Filter out rows already seen, keying on cursor then event.id.

        Args:
            rows: Rows of the current page.
            seen_keys: Set of dedupe keys observed so far.

        Returns:
            Only the rows whose key was not seen before.

        """
        new_rows = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = self._row_dedupe_key(row)
            if key is None or key in seen_keys:
                continue
            seen_keys.add(key)
            new_rows.append(row)
        return new_rows

    def _row_dedupe_key(self, row: dict) -> Any:
        """Compute the dedupe key for a row.

        Args:
            row: Raw SDL match row.

        Returns:
            The row cursor, or the event.id as fallback, or None.

        """
        key = row.get("cursor")
        if key:
            return key
        values = row.get("values")
        if isinstance(values, dict):
            return values.get("event.id")
        return None

    def _should_stop_pagination(
        self,
        est_total: Any,
        unique_count: int,
        new_rows: list,
        page_rows: list,
        page_est: Any,
    ) -> bool:
        """Decide whether paging should stop after the current page.

        Args:
            est_total: estimatedMatchCount reported by the first page.
            unique_count: Unique rows collected so far (after this page).
            new_rows: New rows contributed by the current page.
            page_rows: All rows of the current page.
            page_est: estimatedMatchCount reported by the current page.

        Returns:
            True when all matches are accounted for or no more pages can
            contribute new rows.

        """
        if est_total is not None and unique_count >= est_total:
            return True
        if not new_rows:
            return True
        if (
            len(page_rows) < PAGE_LIMIT
            and page_est is not None
            and page_est <= len(page_rows)
        ):
            return True
        return False

    def _next_cursor(self, rows: list) -> str | None:
        """Get the cursor to resume with after the current page.

        Args:
            rows: Rows of the current page (may be empty).

        Returns:
            The last row's cursor, or None when there is none.

        """
        if not rows or not isinstance(rows[-1], dict):
            return None
        return rows[-1].get("cursor")

    def _extract_page_data(self, final_body: Any) -> dict:
        """Extract the data block from a query response body.

        Args:
            final_body: Query response body (may be malformed).

        Returns:
            The data dict, or an empty dict when absent.

        """
        if not isinstance(final_body, dict):
            return {}
        data = final_body.get("data")
        return data if isinstance(data, dict) else {}

    def _launch_query(self, body: dict) -> tuple[str, str | None]:
        """Launch a SDL v2 long-running query.

        Args:
            body: Full launch request body.

        Returns:
            Tuple of (query_id, forward_tag) where forward_tag may be None.

        Raises:
            SentinelOneAPIError: If the launch fails or returns no query id.
            SentinelOneNetworkError: If a network error occurs.

        """
        endpoint = f"{self.client_api.base_url}/sdl/v2/api/queries"
        self.logger.debug(f"{LOG_PREFIX} Launching SDL query: POST {endpoint}")

        response = self._send_with_rate_limit_retry(
            "post", endpoint, json=body, timeout=REQUEST_TIMEOUT_SECONDS
        )

        if response.status_code != 200:
            self._raise_for_error_response(response, "SDL query launch")

        json_data = response.json()
        if not isinstance(json_data, dict):
            raise SentinelOneAPIError(
                f"SDL query launch returned a non-JSON body: {str(json_data)[:200]}"
            )

        query_id = json_data.get("id")
        if not query_id:
            raise SentinelOneAPIError("SDL query launch response is missing query id")

        return query_id, self._extract_forward_tag(response)

    def _poll_query_to_completion(self, query_id: str, forward_tag: str | None) -> dict:
        """Poll a SDL v2 query until it reports all steps completed.

        Every poll GETs /sdl/v2/api/queries/{id} with lastStepSeen set to
        the last observed stepsCompleted, and echoes the forward tag
        header received at launch. A 404 means the query expired.

        Args:
            query_id: Identifier returned by the launch call.
            forward_tag: Query forward tag to echo on every poll.

        Returns:
            Final query response body (dict).

        Raises:
            SentinelOneAPIError: If polling fails, the query expired, or
                it did not complete within MAX_POLL_ATTEMPTS polls.
            SentinelOneNetworkError: If a network error occurs.

        """
        endpoint = f"{self.client_api.base_url}/sdl/v2/api/queries/{query_id}"
        headers = self._forward_tag_headers(forward_tag)
        last_seen = 0

        for _attempt in range(MAX_POLL_ATTEMPTS):
            params = {"lastStepSeen": last_seen}
            self.logger.debug(
                f"{LOG_PREFIX} Polling SDL query {query_id} (lastStepSeen={last_seen})"
            )

            response = self._send_with_rate_limit_retry(
                "get",
                endpoint,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )

            if response.status_code != 200:
                if response.status_code == 404:
                    raise SentinelOneAPIError(
                        f"SDL query {query_id} expired (HTTP 404): "
                        f"{self._parse_error_response(response)}"
                    )
                self._raise_for_error_response(response, "SDL query poll")

            json_data = response.json()
            if not isinstance(json_data, dict):
                raise SentinelOneAPIError(
                    f"SDL query poll returned a non-JSON body: {str(json_data)[:200]}"
                )

            steps_completed, steps_total = self._extract_progress(json_data)
            if steps_completed is not None:
                last_seen = steps_completed

            if self._is_query_complete(steps_completed, steps_total):
                self.logger.info(
                    f"{LOG_PREFIX} SDL query {query_id} completed "
                    f"(steps {steps_completed}/{steps_total})"
                )
                return json_data

            time.sleep(POLL_INTERVAL_SECONDS)

        raise SentinelOneAPIError(
            f"SDL query {query_id} did not complete within {MAX_POLL_ATTEMPTS} polls"
        )

    def _extract_progress(self, json_data: dict) -> tuple[int | None, int | None]:
        """Extract stepsCompleted/stepsTotal, preferring the top level.

        Args:
            json_data: Query response body.

        Returns:
            Tuple of (steps_completed, steps_total); either may be None.

        """
        data = json_data.get("data")
        if not isinstance(data, dict):
            data = {}

        steps_completed = json_data.get("stepsCompleted", data.get("stepsCompleted"))
        steps_total = json_data.get("stepsTotal", data.get("stepsTotal"))
        return steps_completed, steps_total

    def _is_query_complete(
        self, steps_completed: int | None, steps_total: int | None
    ) -> bool:
        """Check whether the query reports all steps completed.

        Args:
            steps_completed: Steps completed so far (may be None).
            steps_total: Total steps (may be None).

        Returns:
            True when stepsTotal is positive and stepsCompleted reached it.

        """
        return (
            steps_total is not None
            and steps_total > 0
            and steps_completed is not None
            and steps_completed >= steps_total
        )

    def _forward_tag_headers(self, forward_tag: str | None) -> dict | None:
        """Build the header dict echoing the query forward tag.

        Args:
            forward_tag: Forward tag from the launch response (may be None).

        Returns:
            Dict with the forward tag header, or None when no tag exists.

        """
        if not forward_tag:
            return None
        return {FORWARD_TAG_HEADER: forward_tag}

    def _extract_forward_tag(self, response: Any) -> str | None:
        """Extract the query forward tag from launch response headers.

        The header name is matched case-insensitively, per the SDL v2
        contract (x-dataset-query-forward-tag).

        Args:
            response: Launch HTTP response.

        Returns:
            Forward tag value, or None if the header is absent.

        """
        headers = getattr(response, "headers", None)
        if not isinstance(headers, dict):
            return None
        for key, value in headers.items():
            if key.lower() == FORWARD_TAG_HEADER:
                return value
        return None

    def _send_with_rate_limit_retry(
        self, method: str, endpoint: str, **extra_kwargs: Any
    ) -> Any:
        """Send an SDL API request, retrying bounded times on HTTP 429.

        The SDL v2 API rate limit is 8 requests with a 5/s refill, so a
        429 is retried with a growing backoff up to MAX_RATE_LIMIT_RETRIES
        times before failing.

        Args:
            method: Session method to call ("post" or "get").
            endpoint: Full endpoint URL to request.
            extra_kwargs: Keyword arguments forwarded to the session call.

        Returns:
            The first non-429 HTTP response.

        Raises:
            SentinelOneNetworkError: If a connection or timeout error occurs.
            SentinelOneAPIError: If the request fails or the rate limit is
                exhausted.

        """
        attempt = 0
        while True:
            try:
                response = getattr(self.client_api.session, method)(
                    endpoint, **extra_kwargs
                )
            except (ConnectionError, Timeout) as e:
                raise SentinelOneNetworkError(
                    f"Network error making SDL request ({method} {endpoint}): {e}"
                ) from e
            except RequestException as e:
                raise SentinelOneAPIError(
                    f"HTTP request failed for SDL request ({method} {endpoint}): {e}"
                ) from e

            if response.status_code != 429:
                return response

            attempt += 1
            if attempt > MAX_RATE_LIMIT_RETRIES:
                raise SentinelOneAPIError(
                    f"SDL request rate limited (HTTP 429) after "
                    f"{MAX_RATE_LIMIT_RETRIES} retries: {method} {endpoint}"
                )

            backoff = self._rate_limit_backoff_seconds(attempt)
            self.logger.warning(
                f"{LOG_PREFIX} SDL rate limited (HTTP 429); "
                f"retry {attempt}/{MAX_RATE_LIMIT_RETRIES} in {backoff}s"
            )
            time.sleep(backoff)

    def _rate_limit_backoff_seconds(self, attempt: int) -> int:
        """Compute the backoff before the given 429 retry.

        Args:
            attempt: 1-based retry number.

        Returns:
            Backoff in seconds: 5, 10, 15, 15, capped at 15.

        """
        return min(5 * attempt, 15)

    def _raise_for_error_response(self, response: Any, context: str) -> None:
        """Raise SentinelOneAPIError for a non-200 SDL response.

        Args:
            response: HTTP response with a non-200 status.
            context: Human-readable description of the operation.

        Raises:
            SentinelOneAPIError: Always, with the status and parsed details.

        """
        status = response.status_code
        detail = self._parse_error_response(response)
        if status == 404:
            raise SentinelOneAPIError(f"{context} failed with status 404: {detail}")
        raise SentinelOneAPIError(f"{context} failed with status {status}: {detail}")

    def _parse_error_response(self, response: Any) -> str:
        """Parse an SDL error body into a compact detail string.

        Args:
            response: HTTP error response.

        Returns:
            Detail string: "code=...; message=...; details=..." for SDL
            error bodies, or the raw response text otherwise.

        """
        try:
            if hasattr(response, "json"):
                data = response.json()
                if isinstance(data, dict) and ("code" in data or "message" in data):
                    return self._format_sdl_error(data)
            return getattr(response, "text", str(response))
        except Exception as e:
            return f"Error parsing response: {e}"

    def _format_sdl_error(self, data: dict) -> str:
        """Format an SDL v2 error body (code/message/details).

        Args:
            data: Parsed error body.

        Returns:
            Semicolon-joined "key=value" detail string.

        """
        parts = []
        if data.get("code") is not None:
            parts.append(f"code={data['code']}")
        if data.get("message") is not None:
            parts.append(f"message={data['message']}")
        details = data.get("details")
        if details:
            if isinstance(details, list):
                formatted = "; ".join(
                    self._format_detail_item(item) for item in details
                )
                parts.append(f"details={formatted}")
            else:
                parts.append(f"details={details}")
        return "; ".join(parts) if parts else str(data)

    def _format_detail_item(self, item: Any) -> str:
        """Format one SDL error detail entry.

        Args:
            item: Detail entry (dict with field/message, or any other value).

        Returns:
            "field: message" when structured, else the string form.

        """
        if isinstance(item, dict):
            field = item.get("field")
            message = item.get("message")
            if field:
                return f"{field}: {message}"
            return str(message)
        return str(item)

    def _map_row_to_event(self, row: dict) -> dict[str, Any]:
        """Map an SDL v2 match row to the Deep-Visibility-shaped event dict.

        All fields are read with .get() so missing keys become None. The
        fileSha1 key is the contract used by model_threat and by the
        single-sha1 filtering.

        Args:
            row: Raw SDL match row.

        Returns:
            Event dictionary with the expected keys.

        """
        values = row.get("values")
        if not isinstance(values, dict):
            values = {}

        return {
            "fileSha1": values.get("tgt.file.sha1"),
            "fileSha256": values.get("tgt.file.sha256"),
            "fileId": values.get("tgt.file.id"),
            "parentProcessName": values.get("src.process.parent.name"),
            "processName": values.get("src.process.name"),
            "processCmdline": values.get("src.process.cmdline"),
            "parentProcessCmdline": values.get("src.process.parent.cmdline"),
            "hostname": values.get("endpoint.name"),
            "eventType": values.get("event.type"),
            "eventTime": self._format_event_time(values.get("event.time")),
            "eventId": values.get("event.id"),
            "raw": values,
        }

    def _format_event_time(self, event_time: Any) -> str | None:
        """Convert an event.time millisecond epoch to an ISO-8601 Z string.

        Args:
            event_time: Millisecond epoch (int, float, or numeric string).

        Returns:
            ISO-8601 UTC string ending in Z, or None when absent/invalid.

        """
        if event_time is None:
            return None
        if isinstance(event_time, str):
            try:
                event_time = float(event_time)
            except ValueError:
                return None
        try:
            dt = datetime.fromtimestamp(float(event_time) / 1000.0, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return dt.isoformat().replace("+00:00", "Z")

    def _format_timestamp(self, dt: datetime) -> str:
        """Format a datetime for SDL v2 API timestamps.

        SDL v2 expects ISO-8601 UTC with a Z suffix, e.g.
        2026-08-31T00:00:00Z.

        Args:
            dt: Datetime to format (naive values are treated as UTC).

        Returns:
            ISO-8601 UTC string ending in Z.

        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        elif dt.tzinfo != timezone.utc:
            dt = dt.astimezone(timezone.utc)

        return dt.replace(tzinfo=None).isoformat() + "Z"
