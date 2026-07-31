"""Essential tests for Microsoft Defender O365 catalog registration - Gherkin GWT Format."""

from unittest.mock import MagicMock, patch

import pytest

# --------
# Scenarios
# --------


# Scenario Outline: Service appears in the catalog after startup
@pytest.mark.parametrize(
    "service_name, registration_status",
    [
        ("Collector", "Deployed"),
    ],
    ids=[
        "collector_deployed",
    ],
)
def test_service_appears_in_the_catalog_after_startup(
    microsoft_defender_o365_collector_module,
    collector_registration_config_factory,
    service_name,
    registration_status,
):
    """Scenario Outline: Service appears in the catalog after startup"""
    # Given: the platform catalog is accessible, the service is configured with a valid
    # registration, and the service is running with its catalog registration configuration
    mocks, registration_config = _given_service_running_with_registration_configuration(
        microsoft_defender_o365_collector_module,
        collector_registration_config_factory,
        service_name=service_name,
        registration_status=registration_status,
    )

    # When: the platform catalog is queried for registered services
    catalog_entries = _when_platform_catalog_is_queried(mocks)

    # Then: the service appears in the catalog with the expected status
    _then_service_appears_in_catalog(catalog_entries, service_name)
    _then_service_status_is(catalog_entries, service_name, registration_status)


# --------
# Given Methods
# --------


def _given_service_running_with_registration_configuration(
    collector,
    collector_registration_config_factory,
    service_name: str,
    registration_status: str,
) -> tuple[dict[str, MagicMock], object]:
    """Run the collector's main() with a mocked BaseCollector registered in the catalog.

    Args:
        collector: The ``src.collector_main`` module under test.
        collector_registration_config_factory: Polyfactory factory generating dynamic
            CollectorRegistrationConfig fixtures.
        service_name: Name of the service expected to appear in the catalog.
        registration_status: Expected registration status once the service is running.

    Returns:
        A tuple of (mapping of patched dependency name to its mock, the registration
        config used to seed the mocked catalog).

    """
    registration_config = collector_registration_config_factory.build(
        collector_name=service_name,
        status=registration_status,
    )

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
    mocks = {name: patcher.start() for name, patcher in patchers.items()}

    mocks["BaseCollector"].return_value.api.collector.create.return_value = (
        registration_config.model_dump()
    )
    mocks["BaseCollector"].return_value.api.collector.list.return_value = [
        mocks["BaseCollector"].return_value.api.collector.create.return_value,
    ]

    collector.main()

    return mocks, registration_config


# --------
# When Methods
# --------


def _when_platform_catalog_is_queried(mocks: dict[str, MagicMock]) -> list[dict]:
    """Query the platform catalog for the list of registered services.

    Args:
        mocks: Mapping of patched dependency name to its mock.

    Returns:
        The list of catalog entries currently registered on the platform.

    """
    return mocks["BaseCollector"].return_value.api.collector.list()


# --------
# Then Methods
# --------


def _then_service_appears_in_catalog(
    catalog_entries: list[dict], service_name: str
) -> None:
    """Verify that the service appears in the catalog entries.

    Args:
        catalog_entries: The list of catalog entries returned by the platform.
        service_name: Name of the service expected to appear in the catalog.

    """
    assert any(
        entry.get("collector_name") == service_name for entry in catalog_entries
    ), f"'{service_name}' does not appear in the catalog entries: {catalog_entries}"


def _then_service_status_is(
    catalog_entries: list[dict], service_name: str, expected_status: str
) -> None:
    """Verify that the matching service's status equals the expected registration status.

    Args:
        catalog_entries: The list of catalog entries returned by the platform.
        service_name: Name of the service expected to appear in the catalog.
        expected_status: Expected registration status (e.g. "Deployed").

    """
    matching_entries = [
        entry
        for entry in catalog_entries
        if entry.get("collector_name") == service_name
    ]
    assert matching_entries, f"No catalog entry found for '{service_name}'"
    assert matching_entries[0]["status"] == expected_status
