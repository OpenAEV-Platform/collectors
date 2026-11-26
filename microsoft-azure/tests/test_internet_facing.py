"""Tests of asset_internet_facing on the endpoints the Azure collector upserts."""

from unittest.mock import MagicMock

import pytest
from microsoft_azure.network_exposure import internet_facing

NIC_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/"
    "Microsoft.Network/networkInterfaces/vm-nic"
)
PUBLIC_IP_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/"
    "Microsoft.Network/publicIPAddresses/vm-pip"
)


@pytest.mark.parametrize(
    "addresses, types, expected",
    [
        (["20.50.1.10", "10.0.0.4"], (), True),
        (["2603:1020:200::1"], (), True),
        (["10.0.0.4", "192.168.0.11", "fd00::1"], (), False),
        # A public routed block counts like an address.
        (["10.0.0.4", "20.50.1.0/28"], (), True),
        # Loopback, link-local, shared (CGNAT) and invalid addresses say nothing.
        (["127.0.0.1", "169.254.1.1", "100.64.0.1", "not-an-ip", None], (), None),
        ([], (), None),
        # The type the provider declares wins over the range.
        (["20.50.1.10"], ("private",), False),
        (["20.50.1.10", "192.168.0.11"], ("public", "private"), True),
        (["192.168.0.11"], (None,), False),
        # A declared type never turns an unusable address into evidence.
        (["169.254.1.1"], ("public",), None),
    ],
)
def test_internet_facing(addresses, types, expected):
    assert internet_facing(addresses, types) is expected


def _vm(name="vm-1"):
    return {
        "name": name,
        "id": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}",
        "location": "westeurope",
        "properties": {
            "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": "Standard_B2s"},
            "storageProfile": {"osDisk": {"osType": "Linux"}},
            "networkProfile": {"networkInterfaces": [{"id": NIC_ID}]},
        },
    }


def _nic(private_ips, with_public_ip):
    configurations = []
    for index, private_ip in enumerate(private_ips):
        properties = {"privateIPAddress": private_ip}
        if with_public_ip and index == 0:
            properties["publicIPAddress"] = {"id": PUBLIC_IP_ID}
        configurations.append({"properties": properties})
    return {"properties": {"ipConfigurations": configurations}}


def _run(collector, private_ips, public_ip=None, public_lookup_fails=False):
    """Run one collection over a single VM and return the endpoint upserted."""
    nic = _nic(private_ips, with_public_ip=public_ip or public_lookup_fails)

    def api_call(endpoint):
        if endpoint == "/providers/Microsoft.Compute/virtualMachines":
            return {"value": [_vm()]}
        if "/networkInterfaces/" in endpoint:
            return nic
        if "/publicIPAddresses/" in endpoint:
            if public_lookup_fails:
                raise RuntimeError("public IP lookup failed")
            return {"properties": {"ipAddress": public_ip}}
        return None

    collector.resource_groups_list = []
    collector._azure_api_call = MagicMock(side_effect=api_call)
    collector._create_or_get_tag = MagicMock(return_value=None)
    collector.api = MagicMock()
    collector._process_message()
    upserts = collector.api.endpoint.upsert.call_args_list
    return upserts[0].args[0] if upserts else None


def test_vm_with_a_resolved_public_ip_is_internet_facing(secret_collector):
    endpoint = _run(secret_collector, ["10.0.0.4"], public_ip="20.50.1.10")
    assert endpoint["asset_ips"] == ["10.0.0.4", "20.50.1.10"]
    assert endpoint["asset_internet_facing"] is True


def test_vm_with_private_nic_addresses_only_is_not_internet_facing(secret_collector):
    endpoint = _run(secret_collector, ["10.0.0.4", "10.0.1.4"])
    assert endpoint["asset_internet_facing"] is False


def test_failed_public_ip_lookup_never_guesses_true(secret_collector):
    endpoint = _run(secret_collector, ["10.0.0.4"], public_lookup_fails=True)
    assert endpoint["asset_ips"] == ["10.0.0.4"]
    assert endpoint["asset_internet_facing"] is False


def test_public_ip_resource_is_public_by_declaration(secret_collector):
    # A non-routable address on a publicIPAddresses resource (a test range here)
    # is still the address Azure exposes for the VM.
    endpoint = _run(secret_collector, ["10.0.0.4"], public_ip="198.51.100.7")
    assert endpoint["asset_internet_facing"] is True


def test_vm_without_usable_address_sends_no_field(secret_collector):
    endpoint = _run(secret_collector, ["169.254.0.5"])
    assert endpoint["asset_ips"] == ["169.254.0.5"]
    assert "asset_internet_facing" not in endpoint
