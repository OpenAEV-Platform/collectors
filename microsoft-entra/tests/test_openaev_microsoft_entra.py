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

    class CertificateCredential:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    azure_identity_aio.ClientSecretCredential = ClientSecretCredential
    azure_identity_aio.CertificateCredential = CertificateCredential

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
    import asyncio

    real_asyncio_run = asyncio.run
    collector = OpenAEVMicrosoftEntra.__new__(OpenAEVMicrosoftEntra)
    collector.logger = MagicMock()
    collector._configuration = MagicMock()
    collector._configuration.get.side_effect = lambda key: f"value-{key}"
    collector.create_groups = AsyncMock()

    with (
        patch(
            "microsoft_entra.openaev_microsoft_entra.CertificateCredential"
        ) as mock_certificate_credential,
        patch(
            "microsoft_entra.openaev_microsoft_entra.GraphServiceClient"
        ) as mock_graph_client,
        patch(
            "microsoft_entra.openaev_microsoft_entra.asyncio.run"
        ) as mock_asyncio_run,
    ):
        graph_client_instance = MagicMock()
        mock_graph_client.return_value = graph_client_instance
        mock_asyncio_run.side_effect = real_asyncio_run

        collector._process_message()

        mock_certificate_credential.assert_called_once_with(
            tenant_id="value-microsoft_entra_tenant_id",
            client_id="value-microsoft_entra_client_id",
            certificate_data=b"value-microsoft_entra_client_cert_data",
            thumbprint="value-microsoft_entra_client_cert_thumbprint",
            password=b"value-microsoft_entra_client_cert_passphrase",
        )
        mock_graph_client.assert_called_once_with(
            mock_certificate_credential.return_value,
            ["https://graph.microsoft.com/.default"],
        )
        mock_asyncio_run.assert_called_once()
        collector.create_groups.assert_awaited_once_with(graph_client_instance)


def _run_process_message(create_groups):
    """Run _process_message with client secret auth and a mocked async
    credential; answer the credential and the error the run raised."""
    collector = OpenAEVMicrosoftEntra.__new__(OpenAEVMicrosoftEntra)
    collector.logger = MagicMock()
    collector._configuration = MagicMock()
    # Client secret auth: the certificate flag reads as false.
    collector._configuration.get.side_effect = lambda key: (
        None if key == "microsoft_entra_use_certificate_auth" else f"value-{key}"
    )
    collector.create_groups = create_groups
    credential = MagicMock()
    credential.__aenter__ = AsyncMock(return_value=credential)
    credential.__aexit__ = AsyncMock(return_value=False)
    with (
        patch(
            "microsoft_entra.openaev_microsoft_entra.ClientSecretCredential",
            return_value=credential,
        ),
        patch("microsoft_entra.openaev_microsoft_entra.GraphServiceClient"),
    ):
        try:
            collector._process_message()
        except RuntimeError as error:
            return credential, error
    return credential, None


def test_process_message_closes_the_credential_after_the_run():
    """The async credential owns an aiohttp session: it is closed at the end
    of the run, so asyncio does not log 'Unclosed client session' (#691)."""
    create_groups = AsyncMock()
    credential, error = _run_process_message(create_groups)

    assert error is None
    create_groups.assert_awaited_once()
    credential.__aenter__.assert_awaited_once()
    credential.__aexit__.assert_awaited_once()


def test_process_message_closes_the_credential_when_the_run_fails():
    """A failed run still closes the credential, and the error still reaches
    the daemon, which logs it."""
    create_groups = AsyncMock(side_effect=RuntimeError("graph error"))
    credential, error = _run_process_message(create_groups)

    assert str(error) == "graph error"
    create_groups.assert_awaited_once()
    credential.__aexit__.assert_awaited_once()


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

    with (
        patch("microsoft_entra.openaev_microsoft_entra.ClientSecretCredential"),
        patch("microsoft_entra.openaev_microsoft_entra.CertificateCredential"),
        patch("microsoft_entra.openaev_microsoft_entra.GraphServiceClient"),
    ):
        # Ensure there is no current event loop set on this thread, mirroring
        # the daemon runtime environment where the bug was originally caught.
        try:
            asyncio.set_event_loop(None)
        except RuntimeError:
            pass

        collector._process_message()

    collector.create_groups.assert_awaited_once()


def _page(values, next_link=None):
    return types.SimpleNamespace(value=values, odata_next_link=next_link)


def _group(group_id):
    return types.SimpleNamespace(id=group_id, display_name=f"Group {group_id}")


def _user(name, external=False):
    upn = f"{name}_example.com#EXT#@tenant.test" if external else f"{name}@tenant.test"
    return types.SimpleNamespace(
        odata_type="#microsoft.graph.user",
        mail=f"{name}@example.com",
        user_principal_name=upn,
        given_name=name,
        surname="Test",
        department=None,
        job_title=None,
    )


def _collector(include_external=False):
    collector = OpenAEVMicrosoftEntra.__new__(OpenAEVMicrosoftEntra)
    collector.logger = MagicMock()
    collector.include_external = include_external
    collector.api = MagicMock()
    collector.api.team.upsert.side_effect = lambda team: {
        "team_id": f"team-{team['team_name']}"
    }
    collector.api.tag.upsert.side_effect = lambda tag: {
        "tag_id": f"tag-{tag['tag_name']}"
    }
    return collector


def test_create_groups_collects_every_page_of_groups():
    """Regression: the next page of groups was awaited on the request builder
    (missing .get()), which raised TypeError on any tenant with more than one
    page of groups, so groups after the first page were never collected."""
    import asyncio

    collector = _collector()
    collector.create_users = AsyncMock()

    next_builder = MagicMock()
    next_builder.get = AsyncMock(return_value=_page([_group("g3")]))
    graph_client = MagicMock()
    graph_client.groups.get = AsyncMock(
        return_value=_page([_group("g1"), _group("g2")], "https://graph/next")
    )
    graph_client.groups.with_url.return_value = next_builder

    asyncio.run(collector.create_groups(graph_client))

    graph_client.groups.with_url.assert_called_once_with("https://graph/next")
    next_builder.get.assert_awaited_once()
    assert [c.args[0] for c in collector.api.team.upsert.call_args_list] == [
        {"team_name": "Group g1"},
        {"team_name": "Group g2"},
        {"team_name": "Group g3"},
    ]
    assert [c.args[1] for c in collector.create_users.await_args_list] == [
        "g1",
        "g2",
        "g3",
    ]


def test_create_groups_single_page_does_not_follow_a_next_link():
    import asyncio

    collector = _collector()
    collector.create_users = AsyncMock()
    graph_client = MagicMock()
    graph_client.groups.get = AsyncMock(return_value=_page([_group("g1")]))

    asyncio.run(collector.create_groups(graph_client))

    graph_client.groups.with_url.assert_not_called()
    collector.api.team.upsert.assert_called_once_with({"team_name": "Group g1"})
    collector.create_users.assert_awaited_once()


def test_create_users_collects_every_page_of_members():
    import asyncio

    collector = _collector(include_external=False)
    members_builder = MagicMock()
    members_builder.get = AsyncMock(
        return_value=_page(
            [
                _user("alice"),
                types.SimpleNamespace(odata_type="#microsoft.graph.device"),
            ],
            "https://graph/members-next",
        )
    )
    next_builder = MagicMock()
    next_builder.get = AsyncMock(
        return_value=_page([_user("bob"), _user("guest", external=True)])
    )
    members_builder.with_url.return_value = next_builder
    graph_client = MagicMock()
    graph_client.groups.by_group_id.return_value.members = members_builder

    asyncio.run(collector.create_users(graph_client, "g1", {"team_id": "team-1"}))

    members_builder.with_url.assert_called_once_with("https://graph/members-next")
    upserted = [c.args[0] for c in collector.api.user.upsert.call_args_list]
    assert [u["user_email"] for u in upserted] == [
        "alice@example.com",
        "bob@example.com",
    ]
    assert upserted[0] == {
        "user_email": "alice@example.com",
        "user_firstname": "alice",
        "user_lastname": "Test",
        "user_teams": ["team-1"],
        "user_tags": ["tag-source:microsoft-entra", "tag-user-type:internal"],
    }


def test_create_users_includes_external_members_when_configured():
    import asyncio

    collector = _collector(include_external=True)
    members_builder = MagicMock()
    members_builder.get = AsyncMock(return_value=_page([_user("guest", external=True)]))
    graph_client = MagicMock()
    graph_client.groups.by_group_id.return_value.members = members_builder

    asyncio.run(collector.create_users(graph_client, "g1", {"team_id": "team-1"}))

    members_builder.with_url.assert_not_called()
    collector.api.user.upsert.assert_called_once()
    assert collector.api.user.upsert.call_args.args[0]["user_tags"] == [
        "tag-source:microsoft-entra",
        "tag-user-type:external",
    ]
