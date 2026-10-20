from datetime import UTC, datetime, timedelta

from pyoaev.apis.inject_expectation.model.expectation import (  # type: ignore[import-untyped]
    Expectation,
)
from pyoaev.signatures.types import SignatureTypes


def extract_end_date(expectation: Expectation) -> datetime | None:
    """
    Try to extract and format the end date from the expectation
    """
    end_date = None
    for sig in expectation.inject_expectation_signatures or []:
        if sig.type != SignatureTypes.SIG_TYPE_END_DATE:
            continue

        try:
            end_date = datetime.fromisoformat(sig.value)

            if end_date.tzinfo:
                # if there is a timezone, we convert it to UTC
                end_date = end_date.astimezone(UTC)
            else:
                # we consider, if the END_DATE is naive, that is was produced as UTC
                end_date = end_date.replace(tzinfo=UTC)
        except ValueError, TypeError:
            continue

    return end_date


def time_window_over(expectation: Expectation, time_window: timedelta) -> bool:
    """
    Check whether the expectation's time window is over
    """

    end_date = extract_end_date(expectation)
    if not end_date:
        return True

    now = datetime.now(UTC)
    return now > end_date + time_window
