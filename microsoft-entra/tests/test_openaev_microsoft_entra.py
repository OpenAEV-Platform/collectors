import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch


def _install_dependency_stubs() -> None:
    """Install lightweight stubs for optional runtime deps used by the collector module."""

    def ensure_module(name: str) -> types.ModuleType:
        module = sys.modules.get(name)
        if module is None:
            module = types.ModuleType(name)
            sys.modules[name] = module
        return module

    ensure_module("azure")
    ensure_module("azure.identity")
    azure_identity_aio = ensure_module("azure.identity.aio")

    class ClientSecretCredential:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    azure_identity_aio.ClientSecretCredential = ClientSecretCredential

    msgraph_module = ensure_module("msgraph")

    class GraphServiceClient:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    msgraph_module.GraphServiceClient = GraphServiceClient

    ensure_module("pyoaev")
    configuration_module = ensure_module("pyoaev.configuration")
    daemons_module = ensure_module("pyoaev.daemons")

    class Configuration:  # pragma: no cover - import-time fallback only
        pass

    class CollectorDaemon:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    configuration_module.Configuration = Configuration
    daemons_module.CollectorDaemon = CollectorDaemon


try:
    from microsoft_entra.openaev_microsoft_entra import OpenAEVMicrosoftEntra
except ModuleNotFoundError:
    _install_dependency_stubs()
    from microsoft_entra.openaev_microsoft_entra import OpenAEVMicrosoftEntra


def test_process_message_runs_create_groups_via_asyncio_run():
    """_process_message must build the graph client and drive
    create_groups through asyncio.run (not the deprecated
    get_event_loop()/run_until_complete() pattern), so it works
    correctly even when no event loop already exists on the thread."""
    collector = OpenAEVMicrosoftEntra.__new__(OpenAEVMicrosoftEntra)
    collector.logger = MagicMock()
    collector._configuration = MagicMock()
    collector._configuration.get.side_effect = lambda key: f"value-{key}"
    collector.create_groups = AsyncMock()

    with patch(
        "microsoft_entra.openaev_microsoft_entra.ClientSecretCredential"
    ) as mock_credential, patch(
        "microsoft_entra.openaev_microsoft_entra.GraphServiceClient"
    ) as mock_graph_client, patch(
        "microsoft_entra.openaev_microsoft_entra.asyncio.run"
    ) as mock_asyncio_run:
        graph_client_instance = MagicMock()
        mock_graph_client.return_value = graph_client_instance

        collector._process_message()

        mock_credential.assert_called_once_with(
            tenant_id="value-microsoft_entra_tenant_id",
            client_id="value-microsoft_entra_client_id",
            client_secret="value-microsoft_entra_client_secret",
        )
        mock_graph_client.assert_called_once_with(
            mock_credential.return_value, ["https://graph.microsoft.com/.default"]
        )
        mock_asyncio_run.assert_called_once()
        collector.create_groups.assert_called_once_with(graph_client_instance)


def test_process_message_asyncio_run_works_without_existing_event_loop():
    """Regression test for the Python 3.14 incompatibility: asyncio.run()
    must be able to execute create_groups even when the current thread
    has no running/current event loop (unlike the old get_event_loop()
    pattern, which raised RuntimeError in that situation)."""
    import asyncio

    collector = OpenAEVMicrosoftEntra.__new__(OpenAEVMicrosoftEntra)
    collector.logger = MagicMock()
    collector._configuration = MagicMock()
    collector._configuration.get.return_value = "value"
    collector.create_groups = AsyncMock()

    with patch("microsoft_entra.openaev_microsoft_entra.ClientSecretCredential"), patch(
        "microsoft_entra.openaev_microsoft_entra.GraphServiceClient"
    ):
        # Ensure there is no current event loop set on this thread, mirroring
        # the daemon runtime environment where the bug was originally caught.
        try:
            asyncio.set_event_loop(None)
        except RuntimeError:
            pass

        collector._process_message()

    collector.create_groups.assert_awaited_once()
