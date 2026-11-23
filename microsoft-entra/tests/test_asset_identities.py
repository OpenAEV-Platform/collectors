import asyncio
import types
from unittest.mock import AsyncMock, MagicMock

import test_openaev_microsoft_entra as base  # noqa: F401  (installs the stubs)
from microsoft_entra.asset_identities import (
    LINKS_UNAVAILABLE_MESSAGE,
    AssetWriter,
    identity_external_reference,
)
from microsoft_entra.openaev_microsoft_entra import OpenAEVMicrosoftEntra


class _HttpError(Exception):
    def __init__(self, code):
        super().__init__(f"{code}: refused")
        self.response_code = code


def _api():
    api = MagicMock()
    api.endpoint.upsert.side_effect = lambda e: {
        "asset_id": f"asset-{e['asset_external_reference']}"
    }
    api.user.upsert.side_effect = lambda u: {"user_id": f"user-{u['user_email']}"}
    api.team.upsert.side_effect = lambda t: {"team_id": f"team-{t['team_name']}"}
    api.tag.upsert.side_effect = lambda t: {"tag_id": f"tag-{t['tag_name']}"}
    api.http_get.return_value = []
    api.http_post.return_value = {}
    return api


def _collector(api=None, **options):
    collector = OpenAEVMicrosoftEntra.__new__(OpenAEVMicrosoftEntra)
    collector.logger = MagicMock()
    collector.include_external = False
    collector.api = api or _api()
    collector.create_identities = options.get("create_identities", False)
    collector.import_devices = options.get("import_devices", False)
    collector.create_identity_links = options.get("create_identity_links", False)
    collector.assets = AssetWriter(collector.api, collector.logger)
    collector._identity_ids = {}
    return collector


def _page(values, next_link=None):
    return types.SimpleNamespace(value=values, odata_next_link=next_link)


def _user(name, object_id=None):
    return types.SimpleNamespace(
        odata_type="#microsoft.graph.user",
        id=object_id or f"oid-{name}",
        mail=f"{name}@example.com",
        user_principal_name=f"{name}@tenant.test",
        given_name=name,
        surname="Test",
        department=None,
        job_title=None,
    )


def _graph(members, devices=(), managed=(), users_of=None, owners_of=None):
    graph = MagicMock()
    graph.groups.get = AsyncMock(
        return_value=_page([types.SimpleNamespace(id="g1", display_name="G1")])
    )
    graph.groups.by_group_id.return_value.members.get = AsyncMock(
        return_value=_page(list(members))
    )
    graph.devices.get = AsyncMock(return_value=_page(list(devices)))
    graph.device_management.managed_devices.get = AsyncMock(
        return_value=_page(list(managed))
    )
    users_of = users_of or {}
    owners_of = owners_of or {}

    def by_device_id(device_object_id):
        builder = MagicMock()
        builder.registered_users.get = AsyncMock(
            return_value=_page(users_of.get(device_object_id, []))
        )
        builder.registered_owners.get = AsyncMock(
            return_value=_page(owners_of.get(device_object_id, []))
        )
        return builder

    graph.devices.by_device_id.side_effect = by_device_id
    return graph


class _Credential:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _run(collector, graph):
    asyncio.run(collector._collect(_Credential(), graph))


def _device(object_id, device_id, name, os="Windows"):
    return types.SimpleNamespace(
        id=object_id,
        device_id=device_id,
        display_name=name,
        operating_system=os,
        operating_system_version="11",
        trust_type="AzureAd",
    )


def test_defaults_make_exactly_the_calls_of_today():
    api = _api()
    collector = _collector(api)
    graph = _graph([_user("alice")], devices=[_device("d1", "dev-1", "PC1")])

    _run(collector, graph)

    assert [c.args[0]["user_email"] for c in api.user.upsert.call_args_list] == [
        "alice@example.com"
    ]
    api.endpoint.upsert.assert_not_called()
    api.http_get.assert_not_called()
    api.http_post.assert_not_called()
    graph.devices.get.assert_not_called()
    graph.device_management.managed_devices.get.assert_not_called()
    assert len(collector.logger.info.call_args_list) == 1


def test_create_identities_upserts_an_identity_linked_to_the_player():
    api = _api()
    collector = _collector(api, create_identities=True)

    _run(collector, _graph([_user("alice")]))

    identity = api.endpoint.upsert.call_args.args[0]
    assert identity == {
        "asset_name": "alice@tenant.test",
        "asset_external_reference": identity_external_reference("oid-alice"),
        "asset_category": "IDENTITY",
        "asset_subcategory": "USER_ACCOUNT",
        "asset_tags": ["tag-source:microsoft-entra", "tag-user-type:internal"],
        "asset_linked_person": "user-alice@example.com",
    }
    summary = collector.logger.info.call_args.args[0]
    assert "identities: 1 upserted" in summary


def test_identity_is_upserted_once_per_run_and_again_next_run():
    api = _api()
    collector = _collector(api, create_identities=True)
    graph = _graph([_user("alice")])
    graph.groups.get = AsyncMock(
        return_value=_page(
            [
                types.SimpleNamespace(id="g1", display_name="G1"),
                types.SimpleNamespace(id="g2", display_name="G2"),
            ]
        )
    )

    _run(collector, graph)
    assert api.endpoint.upsert.call_count == 1
    _run(collector, graph)
    # The same external reference: the platform updates the same asset.
    refs = {
        c.args[0]["asset_external_reference"]
        for c in api.endpoint.upsert.call_args_list
    }
    assert refs == {identity_external_reference("oid-alice")}


def test_old_platform_without_linked_person_drops_the_field_and_goes_on():
    api = _api()
    calls = []

    def upsert(endpoint):
        calls.append(dict(endpoint))
        if "asset_linked_person" in endpoint:
            raise _HttpError(400)
        return {"asset_id": "asset-1"}

    api.endpoint.upsert.side_effect = upsert
    collector = _collector(api, create_identities=True)

    _run(collector, _graph([_user("alice"), _user("bob")]))

    assert "asset_linked_person" in calls[0]
    assert "asset_linked_person" not in calls[1]
    # Dropped for the rest of the run: bob is sent without it at once.
    assert "asset_linked_person" not in calls[2]
    assert len(calls) == 3
    assert api.user.upsert.call_count == 2


def test_old_platform_without_identity_category_skips_identities_cleanly():
    api = _api()
    api.endpoint.upsert.side_effect = _HttpError(400)
    collector = _collector(api, create_identities=True)

    _run(collector, _graph([_user("alice"), _user("bob")]))

    assert api.user.upsert.call_count == 2
    # alice: with, then without the person link; bob: not tried.
    assert api.endpoint.upsert.call_count == 2
    summary = collector.logger.info.call_args.args[0]
    assert "0 upserted, 0 skipped, 0 failed, 2 unavailable" in summary
    collector.logger.warning.assert_called_once()


def test_entra_device_managed_by_intune_lands_on_the_intune_asset():
    api = _api()
    collector = _collector(api, import_devices=True)
    managed = [types.SimpleNamespace(id="intune-1", azure_a_d_device_id="DEV-1")]
    devices = [_device("d1", "dev-1", "PC1"), _device("d2", "dev-2", "Phone", os="iOS")]

    _run(collector, _graph([], devices=devices, managed=managed))

    upserts = [c.args[0] for c in api.endpoint.upsert.call_args_list]
    assert upserts[0] == {
        "asset_name": "PC1",
        "asset_external_reference": "intune-1",
        "asset_hostname": "PC1",
        "asset_tags": ["tag-source:microsoft-entra"],
    }
    assert upserts[1]["asset_external_reference"] == "entra-device:dev-2"
    assert upserts[1]["asset_category"] == "MOBILE_DEVICE"
    assert upserts[1]["endpoint_platform"] == "iOS"


def test_device_links_and_idempotent_second_run():
    api = _api()
    collector = _collector(
        api, create_identities=True, import_devices=True, create_identity_links=True
    )
    alice = _user("alice")
    graph = _graph(
        [alice],
        devices=[_device("d1", "dev-1", "PC1")],
        users_of={"d1": [alice]},
        owners_of={"d1": [alice]},
    )

    _run(collector, graph)

    identity = f"asset-{identity_external_reference('oid-alice')}"
    posts = [c.args for c in api.http_post.call_args_list]
    assert [
        (p[0], c.kwargs["post_data"])
        for p, c in zip(posts, api.http_post.call_args_list)
    ] == [
        (
            f"/assets/{identity}/links",
            {
                "linked_asset_id": "asset-entra-device:dev-1",
                "asset_link_type": "LOGGED_ON",
            },
        ),
        (
            f"/assets/{identity}/links",
            {"linked_asset_id": "asset-entra-device:dev-1", "asset_link_type": "USES"},
        ),
    ]
    api.http_get.assert_called_once_with(f"/assets/{identity}/links")

    _run(collector, graph)
    # A link written once is not written again, even if removed by hand.
    assert api.http_post.call_count == 2
    assert (
        "links: 0 written, 2 already written" in collector.logger.info.call_args.args[0]
    )


def test_links_unavailable_skip_with_one_info_line():
    for code in (404, 400, 405):
        api = _api()
        api.http_get.side_effect = _HttpError(code)
        collector = _collector(
            api, create_identities=True, import_devices=True, create_identity_links=True
        )
        alice = _user("alice")
        graph = _graph(
            [alice],
            devices=[_device("d1", "dev-1", "PC1"), _device("d2", "dev-2", "PC2")],
            users_of={"d1": [alice], "d2": [alice]},
        )

        _run(collector, graph)

        api.http_post.assert_not_called()
        api.http_get.assert_called_once()
        infos = [c.args[0] for c in collector.logger.info.call_args_list]
        assert infos.count(LINKS_UNAVAILABLE_MESSAGE) == 1
        # Devices and identities are still imported.
        assert api.endpoint.upsert.call_count == 3
        assert "2 unavailable" in infos[-1]


def test_intune_unreadable_falls_back_to_entra_device_keys():
    api = _api()
    collector = _collector(api, import_devices=True)
    graph = _graph([], devices=[_device("d1", "dev-1", "PC1")])
    graph.device_management.managed_devices.get = AsyncMock(
        side_effect=RuntimeError("403 Forbidden")
    )

    _run(collector, graph)

    assert (
        api.endpoint.upsert.call_args.args[0]["asset_external_reference"]
        == "entra-device:dev-1"
    )
