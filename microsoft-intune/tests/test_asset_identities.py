import sys
import types
from unittest.mock import MagicMock


def _install_dependency_stubs() -> None:
    """Stub pyoaev when it is not installed, so the module imports."""

    def ensure_module(name: str) -> types.ModuleType:
        module = sys.modules.get(name)
        if module is None:
            module = types.ModuleType(name)
            sys.modules[name] = module
        return module

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
    from microsoft_intune.openaev_microsoft_intune import OpenAEVMicrosoftIntune
except ModuleNotFoundError:
    _install_dependency_stubs()
    from microsoft_intune.openaev_microsoft_intune import OpenAEVMicrosoftIntune

from microsoft_intune.asset_identities import (
    LINKS_UNAVAILABLE_MESSAGE,
    AssetWriter,
    identity_external_reference,
)


class _HttpError(Exception):
    def __init__(self, code):
        super().__init__(f"{code}: refused")
        self.response_code = code


def _api():
    api = MagicMock()
    api.endpoint.upsert.side_effect = lambda e: {
        "asset_id": f"asset-{e['asset_external_reference']}"
    }
    api.tag.upsert.side_effect = lambda t: {"tag_id": f"tag-{t['tag_name']}"}
    api.http_get.return_value = []
    api.http_post.return_value = {}
    return api


def _device(device_id, user_id="oid-alice", azure_ad_device_id="dev-1"):
    return {
        "id": device_id,
        "deviceName": f"PC-{device_id}",
        "operatingSystem": "Windows",
        "complianceState": "compliant",
        "userPrincipalName": "alice@tenant.test" if user_id else None,
        "userId": user_id,
        "azureADDeviceId": azure_ad_device_id,
    }


def _collector(devices, api=None, **options):
    collector = OpenAEVMicrosoftIntune.__new__(OpenAEVMicrosoftIntune)
    collector.logger = MagicMock()
    collector.api = api or _api()
    collector.create_identities = options.get("create_identities", False)
    collector.create_identity_links = options.get("create_identity_links", False)
    collector.assets = AssetWriter(collector.api, collector.logger)
    collector._identity_ids = {}
    collector._get_managed_devices = MagicMock(return_value=devices)
    return collector


def test_defaults_make_exactly_the_calls_of_today():
    api = _api()
    collector = _collector([_device("i1")], api)

    collector._process_message()

    endpoint = api.endpoint.upsert.call_args.args[0]
    assert api.endpoint.upsert.call_count == 1
    assert endpoint["asset_external_reference"] == "i1"
    assert "asset_metadata" not in endpoint
    api.http_get.assert_not_called()
    api.http_post.assert_not_called()


def test_defaults_do_not_select_the_user_id():
    collector = OpenAEVMicrosoftIntune.__new__(OpenAEVMicrosoftIntune)
    collector.logger = MagicMock()
    collector.device_groups_list = []
    collector.device_filter = None
    collector._graph_api_call = MagicMock(return_value={"value": []})

    collector._get_managed_devices()
    assert ",userId" not in collector._graph_api_call.call_args.args[1]["$select"]

    collector.create_identities = True
    collector._get_managed_devices()
    assert collector._graph_api_call.call_args.args[1]["$select"].endswith(",userId")


def test_create_identities_converges_on_the_entra_identity_key():
    api = _api()
    collector = _collector(
        [_device("i1"), _device("i2", azure_ad_device_id="dev-2")],
        api,
        create_identities=True,
    )

    collector._process_message()

    upserts = [c.args[0] for c in api.endpoint.upsert.call_args_list]
    assert upserts[0]["asset_metadata"] == {"azure_ad_device_id": "dev-1"}
    identities = [u for u in upserts if u.get("asset_category") == "IDENTITY"]
    # One identity per user and run, keyed like the Entra collector.
    assert identities == [
        {
            "asset_name": "alice@tenant.test",
            "asset_external_reference": identity_external_reference("oid-alice"),
            "asset_category": "IDENTITY",
            "asset_subcategory": "USER_ACCOUNT",
        }
    ]
    api.http_post.assert_not_called()


def test_links_written_once_across_runs():
    api = _api()
    collector = _collector(
        [_device("i1")], api, create_identities=True, create_identity_links=True
    )

    collector._process_message()
    collector._process_message()

    identity = f"asset-{identity_external_reference('oid-alice')}"
    api.http_post.assert_called_once_with(
        f"/assets/{identity}/links",
        post_data={"linked_asset_id": "asset-i1", "asset_link_type": "LOGGED_ON"},
    )
    assert "1 already written" in collector.logger.info.call_args.args[0]


def test_links_unavailable_skip_cleanly():
    api = _api()
    api.http_get.side_effect = _HttpError(404)
    collector = _collector(
        [_device("i1"), _device("i2")],
        api,
        create_identities=True,
        create_identity_links=True,
    )

    collector._process_message()

    api.http_post.assert_not_called()
    infos = [c.args[0] for c in collector.logger.info.call_args_list]
    assert infos.count(LINKS_UNAVAILABLE_MESSAGE) == 1
    assert "2 unavailable" in infos[-1]
    collector.logger.error.assert_not_called()


def test_old_platform_refusing_metadata_keeps_importing_devices():
    api = _api()
    calls = []

    def upsert(endpoint):
        calls.append(dict(endpoint))
        if "asset_metadata" in endpoint:
            raise _HttpError(400)
        return {"asset_id": f"asset-{endpoint['asset_external_reference']}"}

    api.endpoint.upsert.side_effect = upsert
    collector = _collector([_device("i1"), _device("i2")], api, create_identities=True)

    collector._process_message()

    device_calls = [c for c in calls if c.get("asset_category") != "IDENTITY"]
    assert [c["asset_external_reference"] for c in device_calls] == ["i1", "i1", "i2"]
    assert "asset_metadata" not in device_calls[2]
    collector.logger.error.assert_not_called()


def test_device_without_primary_user_has_no_identity():
    api = _api()
    collector = _collector(
        [_device("i1", user_id=None)],
        api,
        create_identities=True,
        create_identity_links=True,
    )

    collector._process_message()

    assert api.endpoint.upsert.call_count == 1
    api.http_post.assert_not_called()
