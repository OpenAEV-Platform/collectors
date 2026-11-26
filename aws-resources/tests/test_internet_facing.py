"""Tests of asset_internet_facing on the endpoints the AWS resources collector upserts."""

from unittest.mock import MagicMock, patch

import pytest
from aws_resources import openaev_aws_resources
from aws_resources.network_exposure import internet_facing
from aws_resources.openaev_aws_resources import OpenAEVAWSResources


@pytest.mark.parametrize(
    "addresses, types, expected",
    [
        (["3.120.1.10", "10.0.0.4"], (), True),
        (["2a05:d014::1"], (), True),
        (["10.0.0.4", "172.31.0.11", "fd00::1"], (), False),
        # A public routed block counts like an address.
        (["10.0.0.4", "3.120.1.0/28"], (), True),
        # Loopback, link-local, shared (CGNAT) and invalid addresses say nothing.
        (["127.0.0.1", "169.254.1.1", "100.64.0.1", "not-an-ip", None], (), None),
        ([], (), None),
        # The type the provider declares wins over the range.
        (["3.120.1.10"], ("private",), False),
        (["3.120.1.10", "172.31.0.11"], ("public", "private"), True),
        (["172.31.0.11"], (None,), False),
        # A declared type never turns an unusable address into evidence.
        (["169.254.1.1"], ("public",), None),
    ],
)
def test_internet_facing(addresses, types, expected):
    assert internet_facing(addresses, types) is expected


@pytest.fixture
def collector():
    """Instantiate the collector against a stubbed daemon base class."""
    configuration = MagicMock()
    configuration.get.side_effect = {"aws_regions": "eu-west-3"}.get

    def fake_daemon_init(self, *args, **kwargs):
        self._configuration = configuration
        self.logger = MagicMock()

    with patch.object(
        openaev_aws_resources.CollectorDaemon, "__init__", fake_daemon_init
    ):
        instance = OpenAEVAWSResources(configuration=configuration)
    instance.base_session = MagicMock()
    instance.api = MagicMock()
    instance._create_or_get_tag = MagicMock(return_value=None)
    return instance


def _run(collector, instance):
    """Run one collection over a single instance and return the endpoint upserted."""
    instance = {
        "InstanceId": "i-0123456789abcdef0",
        "InstanceType": "t3.micro",
        "State": {"Name": "running"},
        **instance,
    }
    collector._get_instances_from_region = MagicMock(return_value=[instance])
    collector._process_message()
    upserts = collector.api.endpoint.upsert.call_args_list
    return upserts[0].args[0] if upserts else None


def test_instance_with_a_private_and_a_public_address_is_internet_facing(collector):
    endpoint = _run(
        collector,
        {"PrivateIpAddress": "172.31.0.11", "PublicIpAddress": "3.120.1.10"},
    )
    assert endpoint["asset_ips"] == ["172.31.0.11", "3.120.1.10"]
    assert endpoint["asset_internet_facing"] is True


def test_eni_association_public_ip_is_internet_facing(collector):
    endpoint = _run(
        collector,
        {
            "NetworkInterfaces": [
                {
                    "PrivateIpAddresses": [
                        {
                            "PrivateIpAddress": "172.31.0.11",
                            "Association": {"PublicIp": "3.120.1.10"},
                        }
                    ]
                }
            ]
        },
    )
    assert endpoint["asset_internet_facing"] is True


def test_instance_with_private_addresses_only_is_not_internet_facing(collector):
    endpoint = _run(
        collector,
        {
            "PrivateIpAddress": "172.31.0.11",
            "NetworkInterfaces": [
                {
                    "PrivateIpAddresses": [
                        {"PrivateIpAddress": "172.31.0.11"},
                        {"PrivateIpAddress": "172.31.0.12"},
                    ]
                }
            ],
        },
    )
    assert endpoint["asset_internet_facing"] is False


def test_declared_public_address_wins_over_its_range(collector):
    # The address AWS declares public is public, whatever its range.
    endpoint = _run(
        collector,
        {"PrivateIpAddress": "172.31.0.11", "PublicIpAddress": "198.51.100.7"},
    )
    assert endpoint["asset_internet_facing"] is True


def test_instance_without_usable_address_sends_no_field(collector):
    endpoint = _run(collector, {"PrivateIpAddress": "169.254.0.5"})
    assert endpoint["asset_ips"] == ["169.254.0.5"]
    assert "asset_internet_facing" not in endpoint
