"""Fetch OVHcloud resources and map them to normalized OpenAEV assets.

Everything here is independent from the OpenAEV daemon so it can be unit tested with
recorded API answers: ``collect_assets`` takes any object exposing ``get(path, params)``
(the :class:`ovhcloud.client.OvhClient` in production) and returns ``OvhAsset`` records,
which the daemon turns into agentless endpoints.
"""

import ipaddress
import logging
import re
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote

RESOURCE_DEDICATED_SERVER = "dedicated_server"
RESOURCE_PUBLIC_CLOUD_INSTANCE = "public_cloud_instance"
RESOURCE_VPS = "vps"
RESOURCE_HOSTED_PRIVATE_CLOUD_VM = "hosted_private_cloud_vm"

# IAM states of a service that is no longer usable.
INACTIVE_IAM_STATES = {"SUSPENDED", "EXPIRED"}
# Public Cloud instance statuses of an instance that is gone or never came up.
INACTIVE_INSTANCE_STATUSES = {
    "DELETED",
    "DELETING",
    "SOFT_DELETED",
    "ERROR",
    "BUILD",
    "BUILDING",
}

_WINDOWS_MARKERS = ("windows", "win20", "win-", "win_", "win1")
_LINUX_MARKERS = (
    "linux",
    "debian",
    "ubuntu",
    "centos",
    "rocky",
    "alma",
    "rhel",
    "red hat",
    "redhat",
    "fedora",
    "suse",
    "sles",
    "arch",
    "gentoo",
    "proxmox",
    "coreos",
    "flatcar",
    "alpine",
    "oracle",
    "cloudlinux",
    "kali",
    "slackware",
    "kubernetes",
)
_GENERIC_MARKERS = ("bsd", "esxi", "vmware", "solaris", "hyper-v", "nutanix")


class ApiClient(Protocol):
    """What the inventory needs from an API client."""

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Return the decoded JSON of a GET on ``path``."""


@dataclass(frozen=True)
class InventorySettings:
    """What to collect and how to filter it."""

    collect_dedicated_servers: bool = True
    collect_public_cloud: bool = False
    collect_vps: bool = False
    collect_hosted_private_cloud: bool = False
    public_cloud_project_ids: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    name_include: str | None = None
    name_exclude: str | None = None
    iam_tags: tuple[tuple[str, str], ...] = ()
    skip_inactive: bool = True
    include_public_ipv4: bool = True
    include_public_ipv6: bool = True
    include_private_ips: bool = True
    max_workers: int = 5


@dataclass
class OvhAsset:
    """One OVHcloud machine, normalized for OpenAEV."""

    name: str
    hostname: str
    platform: str
    arch: str
    ips: list[str]
    external_reference: str
    resource_type: str
    cloud_native_type: str
    region: str | None = None
    datacenter: str | None = None
    project: str | None = None
    description: str = ""
    mac_addresses: list[str] = field(default_factory=list)
    iam_tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# -- parsing helpers ----------------------------------------------------------------------


def parse_list(value: str | None) -> tuple[str, ...]:
    """Split a comma separated setting into its non-empty, stripped items."""
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def parse_tags(value: str | None) -> tuple[tuple[str, str], ...]:
    """Parse ``key=value,key2=value2`` into pairs.

    Raises:
        ValueError: When an item has no ``=`` or an empty key.

    """
    pairs = []
    for item in parse_list(value):
        key, sep, tag_value = item.partition("=")
        if not sep or not key.strip():
            raise ValueError(
                f"IAM tag filter '{item}' must be written key=value (several separated "
                "by commas)"
            )
        pairs.append((key.strip(), tag_value.strip()))
    return tuple(pairs)


def platform_from_os(*texts: str | None) -> str:
    """Map OS / image / distribution names to an OpenAEV endpoint platform.

    Returns ``Windows``, ``Linux``, ``Generic`` (a known OS that is neither, e.g. FreeBSD or
    VMware ESXi) or ``Unknown`` (nothing installed or nothing recognized).
    """
    text = " ".join(t for t in texts if t).lower()
    if not text or text.startswith("none"):
        return "Unknown"
    if any(marker in text for marker in _WINDOWS_MARKERS):
        return "Windows"
    if any(marker in text for marker in _LINUX_MARKERS):
        return "Linux"
    if any(marker in text for marker in _GENERIC_MARKERS):
        return "Generic"
    return "Unknown"


def arch_from_os(*texts: str | None) -> str:
    """Map OS / image names to an OpenAEV architecture (``x86_64``, ``arm64``, ``Unknown``)."""
    text = " ".join(t for t in texts if t).lower()
    if not text:
        return "Unknown"
    if any(marker in text for marker in ("arm64", "aarch64", "arm_64")):
        return "arm64"
    if any(marker in text for marker in ("_64", "x64", "x86_64", "amd64", "64bit")):
        return "x86_64"
    return "Unknown"


def _ip_kind(address: str) -> str | None:
    """Classify an address as ``private``, ``ipv4`` or ``ipv6`` (public); None if invalid."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return None
    if ip.is_private:
        return "private"
    return "ipv4" if ip.version == 4 else "ipv6"


def select_ips(addresses: Iterable[str], settings: InventorySettings) -> list[str]:
    """Keep the addresses the IP options allow, deduplicated, in their original order.

    A CIDR block is kept only when it holds a single address (``/32`` or ``/128``): a
    routed block is not one host address.
    """
    selected: list[str] = []
    for raw in addresses:
        if not raw:
            continue
        address = str(raw).strip()
        if "/" in address:
            try:
                network = ipaddress.ip_network(address, strict=False)
            except ValueError:
                continue
            if network.num_addresses != 1:
                continue
            address = str(network.network_address)
        kind = _ip_kind(address)
        if kind is None:
            continue
        if kind == "private" and not settings.include_private_ips:
            continue
        if kind == "ipv4" and not settings.include_public_ipv4:
            continue
        if kind == "ipv6" and not settings.include_public_ipv6:
            continue
        if address not in selected:
            selected.append(address)
    return selected


def routed_blocks(addresses: Iterable[str]) -> list[str]:
    """The CIDR blocks of more than one address (IPv6 /64, failover blocks)."""
    blocks = []
    for raw in addresses:
        try:
            network = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError:
            continue
        if network.num_addresses > 1:
            blocks.append(str(network))
    return blocks


def _iam(resource: dict[str, Any] | None) -> dict[str, Any]:
    if not resource:
        return {}
    return resource.get("iam") or {}


def _iam_tags(resource: dict[str, Any] | None) -> dict[str, str]:
    tags = _iam(resource).get("tags") or {}
    return {str(k): str(v) for k, v in tags.items() if k}


def _iam_inactive(resource: dict[str, Any] | None) -> bool:
    return str(_iam(resource).get("state") or "").upper() in INACTIVE_IAM_STATES


def _strip_dot(value: str | None) -> str | None:
    if not value:
        return None
    return value.rstrip(".") or None


# -- filters -----------------------------------------------------------------------------


class AssetFilter:
    """The name, region and IAM tag filters of the settings, compiled once."""

    def __init__(self, settings: InventorySettings) -> None:
        self.include = (
            re.compile(settings.name_include) if settings.name_include else None
        )
        self.exclude = (
            re.compile(settings.name_exclude) if settings.name_exclude else None
        )
        self.regions = {region.lower() for region in settings.regions}
        self.iam_tags = settings.iam_tags

    def name_allowed(self, *names: str | None) -> bool:
        candidates = [n for n in names if n]
        if self.include and not any(self.include.search(n) for n in candidates):
            return False
        if self.exclude and any(self.exclude.search(n) for n in candidates):
            return False
        return True

    def region_allowed(self, *locations: str | None) -> bool:
        if not self.regions:
            return True
        return any(loc and loc.lower() in self.regions for loc in locations)

    def tags_allowed(self, tags: dict[str, str]) -> bool:
        return all(tags.get(key) == value for key, value in self.iam_tags)

    def allows(self, asset: OvhAsset, *extra_names: str | None) -> bool:
        return (
            self.name_allowed(asset.name, asset.hostname, *extra_names)
            and self.region_allowed(asset.region, asset.datacenter)
            and self.tags_allowed(asset.iam_tags)
        )


# -- collection --------------------------------------------------------------------------


class Inventory:
    """Collect the enabled OVHcloud resource types into ``OvhAsset`` records."""

    def __init__(
        self,
        client: ApiClient,
        settings: InventorySettings,
        logger: logging.Logger | None = None,
    ) -> None:
        self.client = client
        self.settings = settings
        self.filter = AssetFilter(settings)
        self.logger = logger or logging.getLogger(__name__)

    def _map(self, func: Callable[[Any], Any], items: Iterable[Any]) -> list[Any]:
        """Apply ``func`` to every item with at most ``max_workers`` calls in flight."""
        items = list(items)
        if not items:
            return []
        workers = max(1, min(self.settings.max_workers, len(items)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            return list(executor.map(func, items))

    def _safe_get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            return self.client.get(path, params)
        except Exception as err:  # one failing detail call must not stop the run
            self.logger.warning(f"OVHcloud API call {path} failed: {err}")
            return None

    def collect(self) -> list[OvhAsset]:
        """Collect every enabled resource type, filtered."""
        assets: list[OvhAsset] = []
        steps = (
            (self.settings.collect_dedicated_servers, self.dedicated_servers),
            (self.settings.collect_public_cloud, self.public_cloud_instances),
            (self.settings.collect_vps, self.vps),
            (self.settings.collect_hosted_private_cloud, self.hosted_private_cloud_vms),
        )
        for enabled, step in steps:
            if not enabled:
                continue
            try:
                found = step()
            except Exception as err:  # one failing type must not hide the others
                self.logger.error(
                    f"OVHcloud collection step {step.__name__} failed: {err}"
                )
                continue
            self.logger.info(f"OVHcloud {step.__name__}: {len(found)} asset(s) kept")
            assets.extend(found)
        return assets

    # -- dedicated servers (bare metal) ----------------------------------------------------

    def dedicated_servers(self) -> list[OvhAsset]:
        names = self.client.get("/dedicated/server") or []
        results = self._map(self._dedicated_server, names)
        return [asset for asset in results if asset is not None]

    def _dedicated_server(self, service_name: str) -> OvhAsset | None:
        path = f"/dedicated/server/{quote(str(service_name), safe='')}"
        server = self._safe_get(path)
        if not server:
            return None
        if self.settings.skip_inactive and (
            str(server.get("state") or "ok") != "ok" or _iam_inactive(server)
        ):
            self.logger.debug(f"Skipping inactive dedicated server {service_name}")
            return None
        addresses = self._safe_get(f"{path}/ips") or []
        primary = server.get("ip")
        asset = map_dedicated_server(server, [primary, *addresses], self.settings)
        if not self.filter.allows(asset, str(service_name)):
            return None
        return asset

    # -- Public Cloud ------------------------------------------------------------------------

    def public_cloud_instances(self) -> list[OvhAsset]:
        project_ids = list(self.settings.public_cloud_project_ids) or list(
            self.client.get("/cloud/project") or []
        )
        assets: list[OvhAsset] = []
        for project_id in project_ids:
            path = f"/cloud/project/{quote(str(project_id), safe='')}"
            project = self._safe_get(path) or {}
            if self.settings.skip_inactive and (
                str(project.get("status") or "ok") != "ok" or _iam_inactive(project)
            ):
                self.logger.debug(
                    f"Skipping inactive Public Cloud project {project_id}"
                )
                continue
            instances = self._safe_get(f"{path}/instance") or []
            for instance in instances:
                if (
                    self.settings.skip_inactive
                    and str(instance.get("status") or "").upper()
                    in INACTIVE_INSTANCE_STATUSES
                ):
                    continue
                asset = map_public_cloud_instance(
                    instance, str(project_id), project, self.settings
                )
                if self.filter.allows(asset):
                    assets.append(asset)
        return assets

    # -- VPS -----------------------------------------------------------------------------------

    def vps(self) -> list[OvhAsset]:
        names = self.client.get("/vps") or []
        results = self._map(self._vps, names)
        return [asset for asset in results if asset is not None]

    def _vps(self, service_name: str) -> OvhAsset | None:
        path = f"/vps/{quote(str(service_name), safe='')}"
        vps = self._safe_get(path)
        if not vps:
            return None
        if self.settings.skip_inactive and _iam_inactive(vps):
            return None
        addresses = self._safe_get(f"{path}/ips") or []
        image = self._safe_get(f"{path}/images/current") or {}
        asset = map_vps(vps, addresses, image, self.settings)
        if not self.filter.allows(asset, str(service_name)):
            return None
        return asset

    # -- Hosted Private Cloud (VMware) -------------------------------------------------------

    def hosted_private_cloud_vms(self) -> list[OvhAsset]:
        assets: list[OvhAsset] = []
        for service_name in self.client.get("/dedicatedCloud") or []:
            path = f"/dedicatedCloud/{quote(str(service_name), safe='')}"
            service = self._safe_get(path) or {}
            if self.settings.skip_inactive and _iam_inactive(service):
                continue
            for datacenter_id in self._safe_get(f"{path}/datacenter") or []:
                dc_path = f"{path}/datacenter/{datacenter_id}"
                datacenter = self._safe_get(dc_path) or {}
                vm_ids = self._safe_get(f"{dc_path}/vm") or []
                vm_paths = [f"{dc_path}/vm/{vm_id}" for vm_id in vm_ids]
                for vm in self._map(self._safe_get, vm_paths):
                    if not vm:
                        continue
                    deleted = vm.get("powerState") == "deleted"
                    if self.settings.skip_inactive and deleted:
                        continue
                    asset = map_hosted_private_cloud_vm(
                        vm, str(service_name), service, datacenter
                    )
                    if self.filter.allows(asset):
                        assets.append(asset)
        return assets


# -- mapping -----------------------------------------------------------------------------


def map_dedicated_server(
    server: dict[str, Any], addresses: list[str | None], settings: InventorySettings
) -> OvhAsset:
    """Map a ``GET /dedicated/server/{serviceName}`` answer and its IP blocks."""
    service_name = str(server.get("name") or "")
    display_name = _iam(server).get("displayName") or service_name
    os_name = server.get("os")
    datacenter = server.get("datacenter")
    clean = [str(a) for a in addresses if a]
    return OvhAsset(
        name=str(display_name),
        hostname=_strip_dot(server.get("reverse")) or service_name,
        platform=platform_from_os(os_name),
        arch=arch_from_os(os_name),
        ips=select_ips(clean, settings),
        external_reference=service_name,
        resource_type=RESOURCE_DEDICATED_SERVER,
        cloud_native_type="ovh_dedicated_server",
        region=server.get("region"),
        datacenter=datacenter,
        description=(
            "OVHcloud dedicated server - "
            f"Range: {server.get('commercialRange') or 'n/a'}, "
            f"Datacenter: {datacenter or 'n/a'}, OS: {os_name or 'n/a'}"
        ),
        iam_tags=_iam_tags(server),
        metadata={
            "provider": "ovhcloud",
            "resource_type": RESOURCE_DEDICATED_SERVER,
            "service_name": service_name,
            "server_id": server.get("serverId"),
            "commercial_range": server.get("commercialRange"),
            "datacenter": datacenter,
            "region": server.get("region"),
            "availability_zone": server.get("availabilityZone"),
            "rack": server.get("rack"),
            "os": os_name,
            "state": server.get("state"),
            "power_state": server.get("powerState"),
            "routed_blocks": routed_blocks(clean),
            "iam_urn": _iam(server).get("urn"),
        },
    )


def map_public_cloud_instance(
    instance: dict[str, Any],
    project_id: str,
    project: dict[str, Any],
    settings: InventorySettings,
) -> OvhAsset:
    """Map one entry of ``GET /cloud/project/{serviceName}/instance``."""
    image = instance.get("image") or {}
    flavor = instance.get("flavor") or {}
    addresses = [
        str(ip.get("ip")) for ip in instance.get("ipAddresses") or [] if ip.get("ip")
    ]
    name = str(instance.get("name") or instance.get("id") or "")
    region = instance.get("region")
    platform = platform_from_os(
        image.get("type"), image.get("name"), flavor.get("osType")
    )
    arch = arch_from_os(image.get("name"))
    if arch == "Unknown" and platform != "Unknown":
        # Public Cloud images are x86_64 unless their name says otherwise.
        arch = "x86_64"
    project_name = (
        project.get("description") or project.get("projectName") or project_id
    )
    flavor_name = flavor.get("name") or instance.get("flavorId") or "n/a"
    return OvhAsset(
        name=name,
        hostname=name,
        platform=platform,
        arch=arch,
        ips=select_ips(addresses, settings),
        external_reference=str(instance.get("id") or name),
        resource_type=RESOURCE_PUBLIC_CLOUD_INSTANCE,
        cloud_native_type="ovh_public_cloud_instance",
        region=region,
        project=project_id,
        description=(
            f"OVHcloud Public Cloud instance - Project: {project_name}, Region: "
            f"{region or 'n/a'}, Flavor: {flavor_name}, "
            f"Image: {image.get('name') or 'n/a'}"
        ),
        iam_tags=_iam_tags(project),
        metadata={
            "provider": "ovhcloud",
            "resource_type": RESOURCE_PUBLIC_CLOUD_INSTANCE,
            "instance_id": instance.get("id"),
            "project_id": project_id,
            "project_name": project_name,
            "region": region,
            "availability_zone": instance.get("availabilityZone"),
            "flavor": flavor.get("name") or instance.get("flavorId"),
            "image": image.get("name") or instance.get("imageId"),
            "status": instance.get("status"),
        },
    )


def map_vps(
    vps: dict[str, Any],
    addresses: list[str],
    image: dict[str, Any],
    settings: InventorySettings,
) -> OvhAsset:
    """Map a ``GET /vps/{serviceName}`` answer, its IPs and its current image."""
    service_name = str(vps.get("name") or "")
    display_name = (
        vps.get("displayName") or _iam(vps).get("displayName") or service_name
    )
    model = vps.get("model") or {}
    image_name = image.get("name")
    datacenters = model.get("datacenter") or []
    zone = vps.get("zone")
    return OvhAsset(
        name=str(display_name),
        hostname=service_name,
        platform=platform_from_os(image_name),
        arch=arch_from_os(image_name) if image_name else "Unknown",
        ips=select_ips([str(a) for a in addresses], settings),
        external_reference=service_name,
        resource_type=RESOURCE_VPS,
        cloud_native_type="ovh_vps",
        region=zone,
        datacenter=datacenters[0] if len(datacenters) == 1 else None,
        description=(
            f"OVHcloud VPS - Model: {model.get('name') or 'n/a'}, "
            f"Zone: {zone or 'n/a'}, Image: {image_name or 'n/a'}"
        ),
        iam_tags=_iam_tags(vps),
        metadata={
            "provider": "ovhcloud",
            "resource_type": RESOURCE_VPS,
            "service_name": service_name,
            "model": model.get("name"),
            "offer": model.get("offer"),
            "zone": zone,
            "datacenters": datacenters,
            "image": image_name,
            "state": vps.get("state"),
            "vcore": vps.get("vcore"),
            "memory_mb": vps.get("memoryLimit"),
            "iam_urn": _iam(vps).get("urn"),
        },
    )


def map_hosted_private_cloud_vm(
    vm: dict[str, Any],
    service_name: str,
    service: dict[str, Any],
    datacenter: dict[str, Any],
) -> OvhAsset:
    """Map a ``GET /dedicatedCloud/{serviceName}/datacenter/{datacenterId}/vm/{vmId}``.

    The API returns no IP address for a VMware VM: the VM is registered with its MAC
    addresses, and its IPs come from an agent or a later manual edit.
    """
    name = str(vm.get("name") or vm.get("moRef") or vm.get("vmId") or "")
    family = vm.get("guestOsFamily")
    location = service.get("location")
    macs = [
        str(network.get("macAddress"))
        for network in vm.get("networks") or []
        if network.get("macAddress")
    ]
    datacenter_name = datacenter.get("name")
    reference = (
        f"{service_name}/{datacenter.get('datacenterId', '')}/{vm.get('vmId', '')}"
    )
    return OvhAsset(
        name=name,
        hostname=vm.get("hostName") or name,
        platform=platform_from_os(family),
        arch="Unknown",
        ips=[],
        external_reference=reference,
        resource_type=RESOURCE_HOSTED_PRIVATE_CLOUD_VM,
        cloud_native_type="ovh_hosted_private_cloud_vm",
        region=location,
        datacenter=datacenter_name,
        description=(
            f"OVHcloud Hosted Private Cloud VM - Service: {service_name}, "
            f"Datacenter: {datacenter_name or 'n/a'}, "
            f"Cluster: {vm.get('clusterName') or 'n/a'}, "
            f"Guest OS family: {family or 'n/a'}"
        ),
        mac_addresses=macs,
        iam_tags=_iam_tags(service),
        metadata={
            "provider": "ovhcloud",
            "resource_type": RESOURCE_HOSTED_PRIVATE_CLOUD_VM,
            "service_name": service_name,
            "datacenter_id": datacenter.get("datacenterId"),
            "datacenter": datacenter_name,
            "cluster": vm.get("clusterName"),
            "vm_id": vm.get("vmId"),
            "mo_ref": vm.get("moRef"),
            "guest_os_family": family,
            "power_state": vm.get("powerState"),
            "location": location,
        },
    )
