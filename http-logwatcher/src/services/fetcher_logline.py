import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from src.models.logline import AccessLogLine, ErrorLogLine, LogLine
from src.services.exception import (
    HTTPLogwatcherFileError,
    HTTPLogwatcherValidationError,
)

CLF_LOCAL_TIME_REGEX = r"\[([0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}(?: [+-]{1}[0-9]{4})?)\]"
CLF_LOCAL_TIME_PATTERN = "%d/%b/%Y:%H:%M:%S %z"
CLF_IP_REGEX = r"^(.*?) -"
CLF_REQUEST_REGEX = r"\] \"(.*?)\" [0-9]{3} "

DATETIME_STAMP_REGEX = r"([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})"
DATETIME_STAMP_PATTERN = "%Y/%m/%d %H:%M:%S"
VERBOSE_LOG_IP_REGEX = r", client: (.*?),"
VERBOSE_LOG_REQUEST_REGEX = r"request: \"(.*?)\", host"


@dataclass
class FetchResult:
    loglines: list[LogLine] = field(default_factory=list)


class LogLineFetcher:
    def check_valid_datetimes(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> None:
        """Check if the datetimes are valid"""
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise HTTPLogwatcherValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise HTTPLogwatcherValidationError("start_time must be before end_time")

    def check_logfile_exists(self) -> None:
        """Check if the logfiles are available for parsing"""
        if not self.logpath.exists():
            raise HTTPLogwatcherFileError("missing logfile")

    def parse_log(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[LogLine]:
        """
        For a specific logfile (at $logpath), search for datetime according to
        a specific regex ($regex) and translate it into a datetime object
        according to a specific strptime pattern ($pattern)
        """
        lines = []
        for line in self.logpath.open():
            try:
                datetimestamp_str = self.timestamp_regex.search(line).group(1)
            except AttributeError:
                # if the regex didn't match, the group(1) will raise an AttributeError
                continue

            datetimestamp_obj = datetime.strptime(
                datetimestamp_str,
                self.strptime_pattern,
            ).astimezone()
            if datetimestamp_obj < end_time and datetimestamp_obj > start_time:
                try:
                    # if the regex didn't match, the group(1) will raise an AttributeError
                    ip_source = self.ip_regex.search(line).group(1)
                except AttributeError:
                    continue

                try:
                    # if the regex didn't match, the group(1) will raise an AttributeError
                    request = self.request_regex.search(line).group(1)
                except AttributeError:
                    continue

                lines.append(
                    self.logline_type(
                        datetimestamp=datetimestamp_obj,
                        filepath=self.logpath,
                        ip_source=ip_source,
                        request=request,
                    )
                )
        return lines

    def fetch_loglines_for_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> FetchResult:
        """Fetch all loglines for a given time window.

        Returns:
            FetchResult with loglines.
        """
        self.check_valid_datetimes(start_time, end_time)
        self.check_logfile_exists()

        try:
            loglines = self.parse_log(
                start_time,
                end_time,
            )

            return FetchResult(
                loglines=loglines,
            )

        except Exception as e:
            raise HTTPLogwatcherFileError(
                f"Error fetching alerts for time window: {e}"
            ) from e


class AccessLogLineFetcher(LogLineFetcher):
    def __init__(
        self,
        logs_folder_path: Path,
    ) -> None:
        self.logline_type = AccessLogLine
        self.logpath = logs_folder_path / "access.log"
        self.timestamp_regex = re.compile(CLF_LOCAL_TIME_REGEX)
        self.ip_regex = re.compile(CLF_IP_REGEX)
        self.request_regex = re.compile(CLF_REQUEST_REGEX)
        self.strptime_pattern = CLF_LOCAL_TIME_PATTERN


class ErrorLogLineFetcher(LogLineFetcher):
    def __init__(
        self,
        logs_folder_path: Path,
    ) -> None:
        self.logline_type = ErrorLogLine
        self.logpath = logs_folder_path / "error.log"
        self.timestamp_regex = re.compile(DATETIME_STAMP_REGEX)
        self.ip_regex = re.compile(VERBOSE_LOG_IP_REGEX)
        self.request_regex = re.compile(VERBOSE_LOG_REQUEST_REGEX)
        self.strptime_pattern = DATETIME_STAMP_PATTERN
