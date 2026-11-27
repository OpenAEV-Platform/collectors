"""Internet exposure of an asset, computed from the addresses the collector reads.

Same semantics as the OVHcloud collector (``ovhcloud/ovhcloud/inventory.py``), so every
cloud collector of this repository sets ``asset_internet_facing`` the same way. Each
collector image is built from its own directory, so the helper is kept per collector
until the collectors SDK ships a shared home for it.
"""

import ipaddress
from collections.abc import Iterable

PUBLIC = "public"
PRIVATE = "private"


def address_class(raw: str) -> str | None:
    """Classify an address or a CIDR block as ``public`` or ``private``; None if unusable.

    Loopback, link-local, multicast, unspecified and reserved ranges (e.g. the shared
    ``100.64.0.0/10``) say nothing about exposure and are ignored.
    """
    try:
        network = ipaddress.ip_network(str(raw).strip(), strict=False)
    except ValueError:
        return None
    ip = network.network_address
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return None
    if network.is_private:
        return PRIVATE
    if network.is_global:
        return PUBLIC
    return None


def internet_facing(
    addresses: Iterable[str | None], declared_types: Iterable[str | None] = ()
) -> bool | None:
    """Whether an asset is reachable from the Internet, from its RAW addresses.

    ``declared_types`` gives, per address, the type the provider states (``public`` /
    ``private``); an address without one is classified by its range. An unusable
    address (invalid, loopback, link-local, multicast, unspecified, shared) is ignored
    whatever its declared type.

    Returns True when one address is public, False when addresses are known and all are
    private, None when no usable address is known.
    """
    types = list(declared_types)
    classes = set()
    for index, raw in enumerate(addresses):
        if not raw:
            continue
        declared = str(types[index] or "").lower() if index < len(types) else ""
        kind = address_class(str(raw))
        if kind is None:
            continue
        classes.add(declared if declared in (PUBLIC, PRIVATE) else kind)
    if PUBLIC in classes:
        return True
    if PRIVATE in classes:
        return False
    return None
