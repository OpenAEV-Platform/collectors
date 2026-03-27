from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re

from src.models.logline import LogLine
from src.services.exception import (
    HTTPLogwatcherFileError,
    HTTPLogwatcherValidationError,
)

CLF_LOCAL_TIME_REGEX = r"\[([0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}(?: [+-]{1}[0-9]{4})?)\]"
CLF_LOCAL_TIME_PATTERN = "%d/%b/%Y:%H:%M:%S %z"
CLF_IP_REGEX = r"^(.*?) -"

DATETIME_STAMP_REGEX = r"([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})"
DATETIME_STAMP_PATTERN = "%Y/%m/%d %H:%M:%S"
VERBOSE_LOG_IP_REGEX = r", client: (.*?),"


@dataclass
class FetchResult:
    loglines: list[LogLine] = field(default_factory=list)

class LogLineFetcher:
    def __init__(
        self,
        logs_folder_path: Path,
    ) -> None:
        self.access_log = logs_folder_path / "access.log"
        self.error_log = logs_folder_path / "error.log"

        self.access_timestamp_regex = re.compile(CLF_LOCAL_TIME_REGEX)
        self.error_timestamp_regex = re.compile(DATETIME_STAMP_REGEX)

        self.access_ip_regex = re.compile(CLF_IP_REGEX)
        self.error_ip_regex = re.compile(VERBOSE_LOG_IP_REGEX)

    def check_valid_datetimes(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> None:
        """ Check if the datetimes are valid """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise HTTPLogwatcherValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise HTTPLogwatcherValidationError("start_time must be before end_time")

    def check_logfiles_exist(self) -> None:
        """ Check if the logfiles are available for parsing """
        if not self.access_log.exists():
            raise HTTPLogwatcherFileError("missing access.log file")

        if not self.error_log.exists():
            raise HTTPLogwatcherFileError("missing error.log file")

    def parse_log(
        self,
        start_time: datetime,
        end_time: datetime,
        logpath: Path,
        regex: re.Pattern,
        pattern: str,
        ip_regex: re.Pattern,
        source: str,
    ) -> list[LogLine]:
        """
        For a specific logfile (at $logpath), search for datetime according to
        a specific regex ($regex) and translate it into a datetime object
        according to a specific strptime pattern ($pattern)
        """
        lines = []
        for line in logpath.open():
            try:
                datetimestamp_str = regex.search(line).group(1)
                datetimestamp_obj = datetime.strptime(
                    datetimestamp_str,
                    pattern,
                #)
                ).replace(tzinfo=timezone.utc)
            except Exception as _:
                pass
            else:
                if datetimestamp_obj < end_time and datetimestamp_obj > start_time:
                    ip_source = ip_regex.search(line).group(1)
                    lines.append(
                        LogLine(
                            ip_source=ip_source,
                            source=source,
                        )
                    )
        return lines

    def parse_access_log(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[LogLine]:
        """ Search for loglines in access.log using CLF local time format """
        return self.parse_log(
            start_time,
            end_time,
            self.access_log,
            self.access_timestamp_regex,
            CLF_LOCAL_TIME_PATTERN,
            self.access_ip_regex,
            "access",
        )

    def parse_error_log(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[LogLine]:
        """ Search for loglines in error.log using Y/M/D h:m:s time format """
        return self.parse_log(
            start_time,
            end_time,
            self.error_log,
            self.error_timestamp_regex,
            DATETIME_STAMP_PATTERN,
            self.error_ip_regex,
            "error",
        )

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
        self.check_logfiles_exist()

        loglines = []
        try:

            access_loglines = self.parse_access_log(
                start_time,
                end_time,
            )
            loglines.extend(access_loglines)

            error_loglines = self.parse_error_log(
                start_time,
                end_time,
            )
            loglines.extend(error_loglines)

            return FetchResult(
                loglines=loglines,
            )

        except Exception as e:
            raise HTTPLogwatcherFileError(
                f"Error fetching alerts for time window: {e}"
            ) from e
