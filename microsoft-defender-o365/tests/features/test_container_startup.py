"""Essential tests for Microsoft Defender O365 container startup - Gherkin GWT Format."""

from unittest.mock import MagicMock, patch

import pytest

# --------
# Scenarios
# --------


# Scenario Outline: Service process remains alive with no unhandled exceptions
@pytest.mark.parametrize(
    "platform, service_name, base_class, startup_window_seconds",
    [
        ("OpenAEV", "Collector", "BaseCollector", 10),
    ],
    ids=[
        "openaev_collector_base_collector",
    ],
)
def test_service_process_remains_alive_with_no_unhandled_exceptions(
    microsoft_defender_o365_collector_module,
    platform,
    service_name,
    base_class,
    startup_window_seconds,
):
    """Scenario Outline: Service process remains alive with no unhandled exceptions"""
    # Given: a <PLATFORM> instance is running, a docker-compose.yml is configured with the
    # service container, and a minimal <SERVICE_NAME> instantiated from <BASE_CLASS> with a
    # stub Source wired
    mocks = _given_minimal_service_with_stub_source_wired(
        microsoft_defender_o365_collector_module,
        base_class_name=base_class,
    )

    # When: the service process is started via docker-compose (simulated here by calling the
    # collector's main() entry point, exactly as the container's CMD does)
    raised_exception = _when_service_process_is_started(
        microsoft_defender_o365_collector_module
    )

    # Then: the process remains alive in daemon mode and no unhandled exception appears in the
    # service logs within <startup_window_seconds> seconds of startup
    _then_process_remains_alive_in_daemon_mode(mocks, startup_window_seconds)
    _then_no_unhandled_exception_in_service_logs(raised_exception)


# --------
# Given Methods
# --------


def _given_minimal_service_with_stub_source_wired(
    collector,
    base_class_name: str,
) -> dict[str, MagicMock]:
    """Patch the collector module's dependencies with a minimal stub Source wired in.

    Args:
        collector: The ``src.microsoft_defender_o365_collector`` module under test.
        base_class_name: Name of the base daemon class the service is built from
            (e.g. "BaseCollector"), asserted against the module's imported symbol.

    Returns:
        A mapping of patched dependency name to its mock, for use by ``_when``/``_then``.

    """
    assert base_class_name == "BaseCollector"

    patchers = {
        "MicrosoftDefenderO365DataFetcher": patch.object(
            collector, "MicrosoftDefenderO365DataFetcher"
        ),
        "MicrosoftDefenderO365SourceData": patch.object(
            collector, "MicrosoftDefenderO365SourceData"
        ),
        "SUPPORTED_SIGNATURES": patch.object(collector, "SUPPORTED_SIGNATURES"),
        "Source": patch.object(collector, "Source"),
        "BaseCollector": patch.object(collector, "BaseCollector"),
    }
    return {name: patcher.start() for name, patcher in patchers.items()}


# --------
# When Methods
# --------


def _when_service_process_is_started(collector) -> Exception | None:
    """Start the service process by invoking the collector's main() entry point.

    Args:
        collector: The ``src.microsoft_defender_o365_collector`` module under test.

    Returns:
        The exception raised by ``main()``, if any, otherwise ``None``.

    """
    try:
        collector.main()
        return None
    except Exception as err:  # pylint: disable=broad-except
        return err


# --------
# Then Methods
# --------


def _then_process_remains_alive_in_daemon_mode(
    mocks: dict[str, MagicMock], startup_window_seconds: int
) -> None:
    """Verify the daemon's start() was invoked, keeping the process alive.

    Args:
        mocks: Mapping of patched dependency name to its mock.
        startup_window_seconds: Expected startup observation window, in seconds, from the
            scenario's Examples table.

    """
    assert startup_window_seconds > 0
    mocks["BaseCollector"].return_value.start.assert_called_once()


def _then_no_unhandled_exception_in_service_logs(raised_exception: Exception | None) -> None:
    """Verify that no unhandled exception was raised while the service started.

    Args:
        raised_exception: The exception captured while running ``main()``, if any.

    """
    assert raised_exception is None, (
        f"Unhandled exception raised during startup: {raised_exception}"
    )
