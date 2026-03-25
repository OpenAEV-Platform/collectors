from dataclasses import dataclass, field
from datetime import datetime

from src.models.logline import LogLine
from src.services.exception import (
    HTTPLogwatcherFileError,
    HTTPLogwatcherValidationError,
)


@dataclass
class FetchResult:
    loglines: list[LogLine] = field(default_factory=list)

class LogLineFetcher:
    def __init__(self) -> None:
        pass

    def fetch_loglines_for_time_windows(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> FetchResult:
        """Fetch all loglines for a given time window.

        Returns:
            FetchResult with loglines.
        """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise HTTPLogwatcherValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise HTTPLogwatcherValidationError("start_time must be before end_time")

        loglines = []
        try:

            return FetchResult(
                loglines=loglines,
            )

        except Exception as e:
            raise HTTPLogwatcherFileError(
                f"Error fetching alerts for time window: {e}"
            ) from e
