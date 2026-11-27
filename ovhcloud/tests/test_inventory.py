"""Tests of the OVHcloud inventory: toggles, filters, IP options and mapping."""

import pytest
from tests import fixtures
from tests.fixtures import FakeClient

from ovhcloud.inventory import (
    RESOURCE_DEDICATED_SERVER,
    RESOURCE_HOSTED_PRIVATE_CLOUD_VM,
    RESOURCE_PUBLIC_CLOUD_INSTANCE,
    RESOURCE_VPS,
    Inventory,
    InventorySettings,
    arch_from_os,
    internet_facing,
    map_dedicated_server,
    map_public_cloud_instance,
    map_vps,
    parse_list,
    parse_tags,
    platform_from_os,
    select_ips,
)

ALL_TYPES = InventorySettings(
    collect_dedicated_servers=True,
    collect_public_cloud=True,
    collect_vps=True,
    collect_hosted_private_cloud=True,
)


def collect(settings=InventorySettings(), responses=None):
    client = FakeClient(responses)
    return Inventory(client, settings).collect(), client


def by_reference(assets):
    return {asset.external_reference: asset for asset in assets}


# -- OS mapping --


@pytest.mark.parametrize(
    "texts, platform",
    [
        (("debian12_64",), "Linux"),
        (("ubuntu2204-server_64",), "Linux"),
        (("rocky9_64",), "Linux"),
        (("proxmox8_64",), "Linux"),
        (("win2022-std_64",), "Windows"),
        (("windows", "Windows Server 2022"), "Windows"),
        (("freebsd14_64",), "Generic"),
        (("esxi80_64",), "Generic"),
        (("linuxGuest",), "Linux"),
        (("windowsGuest",), "Windows"),
        (("none_64",), "Unknown"),
        ((None,), "Unknown"),
        (("otherGuest",), "Unknown"),
    ],
)
def test_platform_from_os(texts, platform):
    assert platform_from_os(*texts) == platform


@pytest.mark.parametrize(
    "text, arch",
    [
        ("debian12_64", "x86_64"),
        ("ubuntu2204-server-arm64", "arm64"),
        ("Ubuntu 22.04 aarch64", "arm64"),
        ("Ubuntu 22.04", "Unknown"),
        (None, "Unknown"),
    ],
)
def test_arch_from_os(text, arch):
    assert arch_from_os(text) == arch


# -- settings parsing --


def test_parse_list_and_tags():
    assert parse_list(" a, ,b ,") == ("a", "b")
    assert parse_list(None) == ()
    assert parse_tags("env=prod, team = infra") == (("env", "prod"), ("team", "infra"))
    with pytest.raises(ValueError, match="key=value"):
        parse_tags("env")


def test_select_ips_honours_the_ip_options_and_drops_routed_blocks():
    addresses = [
        "51.75.1.10/32",
        "51.75.1.10",
        "2001:41d0:303:1234::/64",
        "2001:41d0:303:1234::1/128",
        "10.10.0.5",
        "178.32.10.0/28",
        "127.0.0.1",
        "not-an-ip",
    ]
    assert select_ips(addresses, InventorySettings()) == [
        "51.75.1.10",
        "2001:41d0:303:1234::1",
        "10.10.0.5",
    ]
    no_private_v6 = InventorySettings(
        include_private_ips=False, include_public_ipv6=False
    )
    assert select_ips(addresses, no_private_v6) == ["51.75.1.10"]
    only_private = InventorySettings(
        include_public_ipv4=False, include_public_ipv6=False
    )
    assert select_ips(addresses, only_private) == ["10.10.0.5"]


# -- internet exposure --


@pytest.mark.parametrize(
    "addresses, types, expected",
    [
        (["51.75.1.10", "10.10.0.5"], (), True),
        (["2001:41d0:303:1234::1"], (), True),
        (["10.10.0.5", "192.168.0.11", "fd00::1"], (), False),
        # A public routed block (failover /28, IPv6 /64) is public exposure.
        (["10.10.0.5", "178.32.10.0/28"], (), True),
        (["2001:41d0:303:1234::/64"], (), True),
        # Loopback, link-local, shared (CGNAT) and invalid addresses say nothing.
        (["127.0.0.1", "169.254.1.1", "100.64.0.1", "not-an-ip", None], (), None),
        ([], (), None),
        # The type the API declares wins over the range.
        (["57.128.10.11"], ("private",), False),
        (["57.128.10.11", "192.168.0.11"], ("public", "private"), True),
        (["192.168.0.11"], (None,), False),
    ],
)
def test_internet_facing(addresses, types, expected):
    assert internet_facing(addresses, types) is expected


def test_dedicated_server_with_a_public_ip_is_internet_facing():
    assets, _ = collect()
    assert all(asset.internet_facing is True for asset in assets)


def test_hiding_public_ips_does_not_make_a_server_look_internal():
    settings = InventorySettings(include_public_ipv4=False, include_public_ipv6=False)
    server = map_dedicated_server(
        fixtures.DEDICATED_SERVER,
        [fixtures.DEDICATED_SERVER["ip"], *fixtures.DEDICATED_SERVER_IPS],
        settings,
    )
    assert server.ips == ["10.10.0.5"]
    assert server.internet_facing is True


def test_dedicated_server_with_private_addresses_only_is_not_internet_facing():
    server = map_dedicated_server(
        {"name": "ns1", "state": "ok"}, [None, "10.10.0.5"], InventorySettings()
    )
    assert server.internet_facing is False


def test_vps_internet_facing():
    settings = InventorySettings(collect_dedicated_servers=False, collect_vps=True)
    (vps,) = collect(settings)[0]
    assert vps.internet_facing is True
    unknown = map_vps(fixtures.VPS, [], {}, InventorySettings())
    assert unknown.internet_facing is None


def test_public_cloud_instance_internet_facing():
    project = fixtures.CLOUD_PROJECT
    public = map_public_cloud_instance(
        fixtures.CLOUD_INSTANCES[0], project["project_id"], project, InventorySettings()
    )
    assert public.internet_facing is True
    private_only = dict(
        fixtures.CLOUD_INSTANCES[0],
        ipAddresses=[
            {"ip": "192.168.0.11", "type": "private", "version": 4},
        ],
    )
    private = map_public_cloud_instance(
        private_only, project["project_id"], project, InventorySettings()
    )
    assert private.internet_facing is False
    no_address = dict(fixtures.CLOUD_INSTANCES[0], ipAddresses=[])
    unknown = map_public_cloud_instance(
        no_address, project["project_id"], project, InventorySettings()
    )
    assert unknown.internet_facing is None


def test_hosted_private_cloud_vm_exposure_is_unknown():
    settings = InventorySettings(
        collect_dedicated_servers=False, collect_hosted_private_cloud=True
    )
    (vm,) = collect(settings)[0]
    assert vm.internet_facing is None


# -- toggles --


def test_default_settings_collect_bare_metal_only():
    assets, client = collect()
    assert {a.resource_type for a in assets} == {RESOURCE_DEDICATED_SERVER}
    assert not [c for c in client.calls if not c.startswith("/dedicated/server")]
    # The suspended server is skipped; the two active ones become one asset each.
    assert sorted(a.external_reference for a in assets) == [
        "ns3001234.ip-51-75-1.eu",
        "ns3005678.ip-51-75-2.eu",
    ]


def test_every_type_is_collected_when_enabled():
    assets, _ = collect(ALL_TYPES)
    counts = {}
    for asset in assets:
        counts[asset.resource_type] = counts.get(asset.resource_type, 0) + 1
    assert counts == {
        RESOURCE_DEDICATED_SERVER: 2,
        RESOURCE_PUBLIC_CLOUD_INSTANCE: 2,
        RESOURCE_VPS: 1,
        RESOURCE_HOSTED_PRIVATE_CLOUD_VM: 1,
    }


def test_inactive_resources_are_kept_when_skip_inactive_is_off():
    settings = InventorySettings(
        collect_dedicated_servers=True, collect_public_cloud=True, skip_inactive=False
    )
    assets, _ = collect(settings)
    references = by_reference(assets)
    assert "ns3009999.ip-51-75-3.eu" in references
    assert "6f1a0000-aaaa-4bbb-8ccc-000000000002" in references


def test_a_failing_type_does_not_hide_the_others():
    responses = fixtures.default_responses()
    del responses["/vps"]
    assets, _ = collect(ALL_TYPES, responses)
    assert RESOURCE_VPS not in {a.resource_type for a in assets}
    assert RESOURCE_DEDICATED_SERVER in {a.resource_type for a in assets}


def test_a_failing_detail_call_skips_only_that_server():
    responses = fixtures.default_responses()
    del responses[f"/dedicated/server/{fixtures.WINDOWS_SERVER['name']}"]
    assets, _ = collect(responses=responses)
    assert [a.external_reference for a in assets] == ["ns3001234.ip-51-75-1.eu"]


# -- mapping --


def test_dedicated_server_mapping():
    assets, _ = collect()
    server = by_reference(assets)["ns3001234.ip-51-75-1.eu"]
    assert server.name == "web-01"
    assert server.hostname == "web-01.example.com"
    assert server.platform == "Linux"
    assert server.arch == "x86_64"
    assert server.ips == ["51.75.1.10", "2001:41d0:303:1234::1", "10.10.0.5"]
    assert server.region == "eu-west-rbx"
    assert server.datacenter == "rbx8"
    assert server.iam_tags == {
        "environment": "production",
        "ovh:type": "dedicatedServer",
    }
    assert server.metadata["commercial_range"] == "advance-1"
    assert server.metadata["routed_blocks"] == [
        "2001:41d0:303:1234::/64",
        "178.32.10.0/28",
    ]

    windows = by_reference(assets)["ns3005678.ip-51-75-2.eu"]
    assert windows.platform == "Windows"
    assert windows.hostname == "ns3005678.ip-51-75-2.eu"
    assert windows.ips == ["51.75.2.20"]


def test_public_cloud_instance_mapping():
    settings = InventorySettings(
        collect_dedicated_servers=False, collect_public_cloud=True
    )
    assets, _ = collect(settings)
    references = by_reference(assets)
    node = references["6f1a0000-aaaa-4bbb-8ccc-000000000001"]
    assert node.name == "k8s-node-1"
    assert node.platform == "Linux"
    assert node.arch == "x86_64"
    assert node.ips == ["57.128.10.11", "2001:41d0:801:1000::1a2b", "192.168.0.11"]
    assert node.region == "GRA11"
    assert node.project == fixtures.CLOUD_PROJECT["project_id"]
    assert node.metadata["flavor"] == "b2-7"
    assert references["6f1a0000-aaaa-4bbb-8ccc-000000000003"].platform == "Windows"
    # The deleted instance is skipped.
    assert "6f1a0000-aaaa-4bbb-8ccc-000000000002" not in references


def test_public_cloud_project_filter_avoids_listing_projects():
    project_id = fixtures.CLOUD_PROJECT["project_id"]
    settings = InventorySettings(
        collect_dedicated_servers=False,
        collect_public_cloud=True,
        public_cloud_project_ids=(project_id,),
    )
    assets, client = collect(settings)
    assert "/cloud/project" not in client.calls
    assert len(assets) == 2


def test_vps_mapping():
    settings = InventorySettings(collect_dedicated_servers=False, collect_vps=True)
    assets, _ = collect(settings)
    (vps,) = assets
    assert vps.name == "monitoring"
    assert vps.hostname == "vps-1a2b3c4d.vps.ovh.net"
    assert vps.platform == "Linux"
    assert vps.ips == ["51.83.1.2", "2001:41d0:304:200::4a1"]
    assert vps.datacenter == "sbg"
    assert vps.metadata["model"] == "vps-value-1-2-40"


def test_hosted_private_cloud_vm_mapping():
    settings = InventorySettings(
        collect_dedicated_servers=False, collect_hosted_private_cloud=True
    )
    assets, _ = collect(settings)
    (vm,) = assets  # the deleted VM is skipped
    assert vm.name == "erp-db"
    assert vm.platform == "Linux"
    assert vm.ips == []
    assert vm.mac_addresses == ["00:50:56:aa:bb:01"]
    assert vm.external_reference == "pcc-145-239-1-1/1/101"
    assert vm.region == "rbx2"


# -- filters --


def test_name_include_and_exclude():
    assets, _ = collect(InventorySettings(name_include="^web-"))
    assert [a.name for a in assets] == ["web-01"]
    assets, _ = collect(InventorySettings(name_exclude="web"))
    assert [a.external_reference for a in assets] == ["ns3005678.ip-51-75-2.eu"]


def test_region_filter_matches_region_or_datacenter_case_insensitively():
    assets, _ = collect(InventorySettings(regions=("RBX8",)))
    assert [a.name for a in assets] == ["web-01"]
    assets, _ = collect(InventorySettings(regions=("eu-west-gra",)))
    assert [a.external_reference for a in assets] == ["ns3005678.ip-51-75-2.eu"]


def test_iam_tag_filter():
    assets, _ = collect(InventorySettings(iam_tags=(("environment", "production"),)))
    assert [a.name for a in assets] == ["web-01"]
    assets, _ = collect(InventorySettings(iam_tags=(("environment", "dev"),)))
    assert assets == []
