"""Recorded OVHcloud API answers (anonymized) and a fake client that serves them."""

from typing import Any

DEDICATED_SERVER = {
    "name": "ns3001234.ip-51-75-1.eu",
    "serverId": 1234567,
    "commercialRange": "advance-1",
    "datacenter": "rbx8",
    "region": "eu-west-rbx",
    "availabilityZone": "eu-west-rbx-a",
    "rack": "R08B12",
    "os": "debian12_64",
    "ip": "51.75.1.10",
    "reverse": "web-01.example.com.",
    "state": "ok",
    "powerState": "poweron",
    "iam": {
        "id": "9f1c2f3a-0000-4000-8000-000000000001",
        "urn": "urn:v1:eu:resource:dedicatedServer:ns3001234.ip-51-75-1.eu",
        "displayName": "web-01",
        "state": "OK",
        "tags": {"environment": "production", "ovh:type": "dedicatedServer"},
    },
}

DEDICATED_SERVER_IPS = [
    "51.75.1.10/32",
    "2001:41d0:303:1234::/64",
    "2001:41d0:303:1234::1/128",
    "10.10.0.5/32",
    "178.32.10.0/28",
]

WINDOWS_SERVER = {
    "name": "ns3005678.ip-51-75-2.eu",
    "serverId": 1234568,
    "commercialRange": "rise-2",
    "datacenter": "gra3",
    "region": "eu-west-gra",
    "availabilityZone": "eu-west-gra-a",
    "rack": "G03A01",
    "os": "win2022-std_64",
    "ip": "51.75.2.20",
    "reverse": None,
    "state": "ok",
    "powerState": "poweron",
    "iam": {
        "id": "9f1c2f3a-0000-4000-8000-000000000002",
        "urn": "urn:v1:eu:resource:dedicatedServer:ns3005678.ip-51-75-2.eu",
        "displayName": "ns3005678.ip-51-75-2.eu",
        "state": "OK",
        "tags": {"environment": "staging"},
    },
}

SUSPENDED_SERVER = {
    **WINDOWS_SERVER,
    "name": "ns3009999.ip-51-75-3.eu",
    "ip": "51.75.3.30",
    "iam": {"state": "SUSPENDED", "tags": {}},
}

CLOUD_PROJECT = {
    "project_id": "0123456789abcdef0123456789abcdef",
    "description": "Production",
    "projectName": "prod",
    "status": "ok",
    "iam": {"state": "OK", "tags": {"environment": "production"}},
}

CLOUD_INSTANCES = [
    {
        "id": "6f1a0000-aaaa-4bbb-8ccc-000000000001",
        "name": "k8s-node-1",
        "region": "GRA11",
        "availabilityZone": None,
        "status": "ACTIVE",
        "flavorId": "b2-7",
        "imageId": "img-1",
        "flavor": {"name": "b2-7", "osType": "linux"},
        "image": {"name": "Ubuntu 22.04", "type": "linux"},
        "ipAddresses": [
            {"ip": "57.128.10.11", "type": "public", "version": 4, "networkId": "n1"},
            {
                "ip": "2001:41d0:801:1000::1a2b",
                "type": "public",
                "version": 6,
                "networkId": "n1",
            },
            {"ip": "192.168.0.11", "type": "private", "version": 4, "networkId": "n2"},
        ],
    },
    {
        "id": "6f1a0000-aaaa-4bbb-8ccc-000000000002",
        "name": "gone",
        "region": "GRA11",
        "status": "DELETED",
        "flavorId": "b2-7",
        "imageId": "img-1",
        "ipAddresses": [],
    },
    {
        "id": "6f1a0000-aaaa-4bbb-8ccc-000000000003",
        "name": "win-bastion",
        "region": "BHS5",
        "status": "ACTIVE",
        "flavorId": "win-b2-15",
        "imageId": "img-2",
        "flavor": {"name": "win-b2-15", "osType": "windows"},
        "image": {"name": "Windows Server 2022 Standard (Desktop)", "type": "windows"},
        "ipAddresses": [
            {"ip": "15.235.1.2", "type": "public", "version": 4, "networkId": "n1"}
        ],
    },
]

VPS = {
    "name": "vps-1a2b3c4d.vps.ovh.net",
    "displayName": "monitoring",
    "zone": "Region OpenStack: os-sbg5",
    "state": "running",
    "vcore": 2,
    "memoryLimit": 4096,
    "model": {
        "name": "vps-value-1-2-40",
        "offer": "VPS Value",
        "datacenter": ["sbg"],
        "version": "2019v1",
    },
    "iam": {"state": "OK", "tags": {"team": "infra"}},
}

VPS_IPS = ["51.83.1.2", "2001:41d0:304:200::4a1"]

VPS_IMAGE = {"id": "img-vps", "name": "Rocky Linux 9"}

HPC_SERVICE = {
    "serviceName": "pcc-145-239-1-1",
    "location": "rbx2",
    "iam": {"state": "OK", "tags": {}},
}

HPC_DATACENTER = {"datacenterId": 1, "name": "pcc-145-239-1-1_datacenter1"}

HPC_VMS = {
    101: {
        "vmId": 101,
        "moRef": "vm-101",
        "name": "erp-db",
        "hostName": "esx-01.pcc-145-239-1-1.ovh.de",
        "clusterName": "Cluster1",
        "guestOsFamily": "linuxGuest",
        "powerState": "poweredOn",
        "networks": [{"label": "VM Network", "macAddress": "00:50:56:aa:bb:01"}],
    },
    102: {
        "vmId": 102,
        "moRef": "vm-102",
        "name": "old-template",
        "guestOsFamily": "windowsGuest",
        "powerState": "deleted",
        "networks": [],
    },
}


def default_responses() -> dict[str, Any]:
    """Every API path the collector reads, mapped to its recorded answer."""
    servers = {
        DEDICATED_SERVER["name"]: (DEDICATED_SERVER, DEDICATED_SERVER_IPS),
        WINDOWS_SERVER["name"]: (WINDOWS_SERVER, ["51.75.2.20/32"]),
        SUSPENDED_SERVER["name"]: (SUSPENDED_SERVER, ["51.75.3.30/32"]),
    }
    responses: dict[str, Any] = {"/dedicated/server": list(servers)}
    for name, (server, ips) in servers.items():
        responses[f"/dedicated/server/{name}"] = server
        responses[f"/dedicated/server/{name}/ips"] = ips
    project_id = CLOUD_PROJECT["project_id"]
    responses["/cloud/project"] = [project_id]
    responses[f"/cloud/project/{project_id}"] = CLOUD_PROJECT
    responses[f"/cloud/project/{project_id}/instance"] = CLOUD_INSTANCES
    responses["/vps"] = [VPS["name"]]
    responses[f"/vps/{VPS['name']}"] = VPS
    responses[f"/vps/{VPS['name']}/ips"] = VPS_IPS
    responses[f"/vps/{VPS['name']}/images/current"] = VPS_IMAGE
    service = HPC_SERVICE["serviceName"]
    responses["/dedicatedCloud"] = [service]
    responses[f"/dedicatedCloud/{service}"] = HPC_SERVICE
    responses[f"/dedicatedCloud/{service}/datacenter"] = [1]
    responses[f"/dedicatedCloud/{service}/datacenter/1"] = HPC_DATACENTER
    responses[f"/dedicatedCloud/{service}/datacenter/1/vm"] = list(HPC_VMS)
    for vm_id, vm in HPC_VMS.items():
        responses[f"/dedicatedCloud/{service}/datacenter/1/vm/{vm_id}"] = vm
    return responses


class FakeClient:
    """Serves recorded answers by path and records every call."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = default_responses() if responses is None else responses
        self.calls: list[str] = []

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        self.calls.append(path)
        if path not in self.responses:
            raise KeyError(f"unexpected OVHcloud API call {path}")
        return self.responses[path]
