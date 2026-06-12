"""Essential tests for Template Data Fetcher service - Gherkin GWT Format."""

import pytest
from src.services.exception import TemplateValidationError
from src.services.fetcher_data import FetcherData

# --------
# Scenarios
# --------


# Scenario: Fetch data for time window successfully
def test_fetch_data_for_time_window_successfully():
    """Scenario: Fetch data for time window successfully."""
    # Given: A valid data fetcher
    fetcher = _given_valid_data_fetcher()
    # Given: A valid time window
    time_window = _given_valid_time_window()
    # When: I fetch data for the time window
    data = _when_fetch_data_for_time_window(fetcher, time_window)

    # Then: Data should be returned successfully
    _then_data_returned_successfully(data)


# Scenario: Handle invalid time window
def test_handle_invalid_time_window():
    """Scenario: Handle invalid time window."""
    # Given: A valid data fetcher
    fetcher = _given_valid_data_fetcher()
    # Given: An invalid time window
    invalid_time_window = _given_invalid_time_window()

    # When: I attempt to fetch data with invalid time window
    # Then: A validation error should be raised
    _when_fetch_data_then_validation_error_raised(fetcher, invalid_time_window)


# --------
# Given Methods
# --------


# Given: A valid data fetcher
def _given_valid_data_fetcher():
    """Create a valid data fetcher for testing.

    Returns:
        Initialized FetcherData instance.

    """
    return FetcherData()


# Given: A valid time window
def _given_valid_time_window():
    """Create a valid time window for testing.

    Returns:
        Valid timedelta object.

    """
    from datetime import timedelta

    return timedelta(hours=24)


# Given: An invalid time window
def _given_invalid_time_window():
    """Create an invalid time window.

    Returns:
        Invalid time window (None).

    """
    return None


# --------
# When Methods
# --------


# When: I initialize the data fetcher
def _when_initialize_data_fetcher():
    """Initialize data fetcher.

    Returns:
        Initialized FetcherData instance.

    """
    return FetcherData()


# When: I fetch data for the time window
def _when_fetch_data_for_time_window(fetcher, time_window):
    """Fetch data for given time window.

    Args:
        fetcher: The data fetcher instance.
        time_window: Time window to fetch data for.

    Returns:
        List of fetched data.

    """
    from datetime import datetime, timezone

    end_time = datetime.now(timezone.utc)
    start_time = end_time - time_window
    return fetcher.fetch_data_for_time_window(start_time, end_time)


# When: I attempt to fetch data and expect validation error
def _when_fetch_data_then_validation_error_raised(fetcher, invalid_time_window):
    """Attempt to fetch data and expect validation error.

    Args:
        fetcher: The data fetcher instance.
        invalid_time_window: Invalid time window to test.

    """
    from datetime import datetime, timezone

    if invalid_time_window is not None:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - invalid_time_window
        with pytest.raises(TemplateValidationError):
            fetcher.fetch_data_for_time_window(start_time, end_time)
    else:
        with pytest.raises(TemplateValidationError):
            fetcher.fetch_data_for_time_window(None, None)


# --------
# Then Methods
# --------


# Then: The data fetcher should be initialized successfully
def _then_data_fetcher_initialized_successfully(fetcher):
    """Verify data fetcher was initialized successfully.

    Args:
        fetcher: The data fetcher instance to verify.

    """
    assert fetcher is not None  # noqa: S101
    assert fetcher.logger is not None  # noqa: S101


# Then: data should be returned successfully
def _then_data_returned_successfully(data):
    """Verify data were returned successfully.

    Args:
        data: The fetched data to verify.

    """
    assert isinstance(data, list)  # noqa: S101
    assert len(data) > 0  # noqa: S101

    # Basic verification that we got data back
    from src.services.model_data import TemplateData

    assert all(  # noqa: S101
        isinstance(single_data, TemplateData) for single_data in data
    )
