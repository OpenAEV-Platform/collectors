"""Tests of the configuration: defaults, credentials, env parsing and the daemon."""

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from ovhcloud import openaev_ovhcloud
from ovhcloud.configuration.collector_config_override import CollectorConfigOverride
from ovhcloud.configuration.config_loader import ConfigLoader
from ovhcloud.inventory import OvhAsset
from ovhcloud.openaev_ovhcloud import OpenAEVOvhcloud, build_endpoint, tag_names

APPLICATION_KEYS = {
    "ovhcloud_application_key": "ak",
    "ovhcloud_application_secret": "as",
    "ovhcloud_consumer_key": "ck",
}


def test_defaults_collect_bare_metal_only():
    config = CollectorConfigOverride(**APPLICATION_KEYS)
    assert config.id == "openaev_ovhcloud"
    assert config.period.total_seconds() == 3600
    assert config.ovhcloud_endpoint == "ovh-eu"
    assert config.ovhcloud_collect_dedicated_servers is True
    assert config.ovhcloud_collect_public_cloud is False
    assert config.ovhcloud_collect_vps is False
    assert config.ovhcloud_collect_hosted_private_cloud is False
    assert config.ovhcloud_skip_inactive is True


def test_oauth2_credentials_are_enough():
    config = CollectorConfigOverride(
        ovhcloud_client_id="id", ovhcloud_client_secret="s"
    )
    assert config.ovhcloud_client_secret.get_secret_value() == "s"


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"ovhcloud_application_key": "ak", "ovhcloud_application_secret": "as"},
        {"ovhcloud_client_id": "id"},
    ],
)
def test_incomplete_credentials_are_refused(values):
    with pytest.raises(ValidationError, match="credentials are incomplete"):
        CollectorConfigOverride(**values)


def test_invalid_endpoint_regex_and_tags_are_refused():
    with pytest.raises(ValidationError):
        CollectorConfigOverride(**APPLICATION_KEYS, ovhcloud_endpoint="ovh-mars")
    with pytest.raises(ValidationError, match="invalid regular expression"):
        CollectorConfigOverride(**APPLICATION_KEYS, ovhcloud_name_include="(")
    with pytest.raises(ValidationError, match="key=value"):
        CollectorConfigOverride(**APPLICATION_KEYS, ovhcloud_iam_tags="env")


def test_environment_variables_reach_the_daemon_configuration(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name, value in {
        "OPENAEV_URL": "http://openaev:8080",
        "OPENAEV_TOKEN": "token",
        "COLLECTOR_ID": "c1",
        "COLLECTOR_OVHCLOUD_ENDPOINT": "ovh-ca",
        "COLLECTOR_OVHCLOUD_CLIENT_ID": "id",
        "COLLECTOR_OVHCLOUD_CLIENT_SECRET": "secret",
        "COLLECTOR_OVHCLOUD_COLLECT_VPS": "true",
        "COLLECTOR_OVHCLOUD_REGIONS": "GRA11,rbx",
        "COLLECTOR_OVHCLOUD_MAX_WORKERS": "3",
    }.items():
        monkeypatch.setenv(name, value)
    configuration = ConfigLoader().to_daemon_config()
    assert configuration.get("ovhcloud_endpoint") == "ovh-ca"
    assert configuration.get("ovhcloud_client_secret") == "secret"
    # pyoaev's Configuration returns booleans as 0 / 1.
    assert bool(configuration.get("ovhcloud_collect_vps")) is True
    assert bool(configuration.get("ovhcloud_collect_dedicated_servers")) is True
    assert bool(configuration.get("ovhcloud_collect_public_cloud")) is False
    assert configuration.get("ovhcloud_regions") == "GRA11,rbx"
    assert configuration.get("ovhcloud_max_workers") == 3


def _asset(**overrides):
    values = dict(
        name="web-01",
        hostname="web-01.example.com",
        platform="Linux",
        arch="x86_64",
        ips=["51.75.1.10"],
        external_reference="ns3001234.ip-51-75-1.eu",
        resource_type="dedicated_server",
        cloud_native_type="ovh_dedicated_server",
        region="eu-west-rbx",
        datacenter="rbx8",
        iam_tags={"environment": "Production", "ovh:type": "dedicatedServer"},
        metadata={"provider": "ovhcloud", "rack": None, "routed_blocks": []},
    )
    values.update(overrides)
    return OvhAsset(**values)


def test_build_endpoint_payload():
    endpoint = build_endpoint(_asset(), ["t1", "t2"])
    assert endpoint["asset_external_reference"] == "ns3001234.ip-51-75-1.eu"
    assert endpoint["asset_category"] == "HOST"
    assert endpoint["asset_subcategory"] == "SERVER"
    assert endpoint["asset_cloud_provider"] == "OTHER"
    assert endpoint["asset_cloud_region"] == "eu-west-rbx"
    assert endpoint["asset_tags"] == ["t1", "t2"]
    assert endpoint["asset_metadata"] == {"provider": "ovhcloud"}
    assert "asset_mac_addresses" not in endpoint
    # Unknown exposure is omitted, never sent as false.
    assert "asset_internet_facing" not in endpoint

    vm_asset = _asset(
        resource_type="hosted_private_cloud_vm", region=None, mac_addresses=["aa"]
    )
    vm = build_endpoint(vm_asset, [])
    assert vm["asset_subcategory"] == "VIRTUAL_MACHINE"
    assert vm["asset_cloud_region"] == "rbx8"
    assert vm["asset_mac_addresses"] == ["aa"]
    assert "asset_tags" not in vm


@pytest.mark.parametrize("facing", [True, False])
def test_build_endpoint_sends_the_known_internet_exposure(facing):
    endpoint = build_endpoint(_asset(internet_facing=facing), [])
    assert endpoint["asset_internet_facing"] is facing


def test_tag_names_skip_ovh_system_tags_and_honour_the_toggle():
    names = [name for name, _ in tag_names(_asset(), include_ovh_tags=True)]
    assert names == [
        "source:ovhcloud",
        "ovh-type:dedicated_server",
        "region:eu-west-rbx",
        "datacenter:rbx8",
        "ovh-environment:production",
    ]
    names = [name for name, _ in tag_names(_asset(), include_ovh_tags=False)]
    assert "ovh-environment:production" not in names


def _daemon(values):
    configuration = MagicMock()
    configuration.get.side_effect = values.get

    def fake_init(self, *args, **kwargs):
        self._configuration = configuration
        self.logger = MagicMock()
        self.api = MagicMock()

    with patch.object(openaev_ovhcloud.CollectorDaemon, "__init__", fake_init):
        return OpenAEVOvhcloud(configuration=configuration)


def test_a_bare_metal_run_upserts_one_endpoint_per_dedicated_server():
    from tests.fixtures import FakeClient

    daemon = _daemon(
        {
            "ovhcloud_collect_dedicated_servers": True,
            "ovhcloud_skip_inactive": True,
            "ovhcloud_include_public_ipv4": True,
            "ovhcloud_include_public_ipv6": True,
            "ovhcloud_include_private_ips": True,
            "ovhcloud_import_tags": True,
        }
    )
    daemon.client = FakeClient()
    daemon.api.tag.upsert.side_effect = lambda data: {
        "tag_id": f"id-{data['tag_name']}"
    }

    daemon._process_message()

    payloads = [call.args[0] for call in daemon.api.endpoint.upsert.call_args_list]
    assert sorted(p["asset_external_reference"] for p in payloads) == [
        "ns3001234.ip-51-75-1.eu",
        "ns3005678.ip-51-75-2.eu",
    ]
    web = next(p for p in payloads if p["asset_name"] == "web-01")
    assert web["asset_ips"] == ["51.75.1.10", "2001:41d0:303:1234::1", "10.10.0.5"]
    assert "id-source:ovhcloud" in web["asset_tags"]
    # Each tag is upserted once per run, not once per asset.
    tag_calls = [c.args[0]["tag_name"] for c in daemon.api.tag.upsert.call_args_list]
    assert tag_calls.count("source:ovhcloud") == 1
