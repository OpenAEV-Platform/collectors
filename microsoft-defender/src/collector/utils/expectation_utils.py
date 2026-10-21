from datetime import UTC, datetime, timedelta

from pyoaev.apis.inject_expectation.model.expectation import (  # type: ignore[import-untyped]
    Expectation,
)
from pyoaev.signatures.types import SignatureTypes


def extract_date(
    expectation: Expectation, signature_type: SignatureTypes
) -> datetime | None:
    """
    Try to extract and format the end date from the expectation
    """
    date = None
    for sig in expectation.inject_expectation_signatures or []:
        if sig.type != signature_type:
            continue

        try:
            date = datetime.fromisoformat(sig.value)

            if date.tzinfo:
                # if there is a timezone, we convert it to UTC
                date = date.astimezone(UTC)
            else:
                # we consider, if the END_DATE is naive, that is was produced as UTC
                date = date.replace(tzinfo=UTC)
        except ValueError, TypeError:
            continue

    return date


def extract_end_date(expectation: Expectation) -> datetime | None:
    end_date = extract_date(expectation, SignatureTypes.SIG_TYPE_END_DATE)
    return end_date


def extract_start_date(expectation: Expectation) -> datetime | None:
    start_date = extract_date(expectation, SignatureTypes.SIG_TYPE_START_DATE)
    return start_date


def time_window_over(expectation: Expectation, time_window: timedelta) -> bool:
    """
    Check whether the expectation's time window is over.
    Try with the end date first,
    if unavailable use the start date but readjust
    the time window with a factor of 1.5.
    If also unavailable, just call it a day, because something is wrong here.
    """
    factor = 1.0
    date = extract_end_date(expectation)

    if not date:
        # looking for the start date and readjusting the factor
        factor = 1.5
        date = extract_start_date(expectation)

    if not date:
        # if there is neither start_date nor end_date, drop it
        return True

    now = datetime.now(UTC)
    time_window = factor * time_window

    return now > date + time_window
