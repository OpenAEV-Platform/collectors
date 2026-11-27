"""Identity assets and asset links written by the Microsoft collectors.

Everything here sits behind an option that is off by default. Every write
degrades instead of failing the run: an OpenAEV that does not know a field, the
IDENTITY category or the asset links API answers an error, the feature is
switched off for the rest of the run with one log line, and the rest of the
import goes on exactly as without the option.

The same module ships in the Microsoft Entra and Microsoft Intune collectors,
so both key an identity the same way and converge on one identity asset.
"""

from collections import Counter
from typing import Any

# One identity asset per Entra user object, whichever collector writes it.
IDENTITY_EXTERNAL_REFERENCE_PREFIX = "entra-user:"
# An Entra device that Intune does not manage (or whose Intune id is unknown).
DEVICE_EXTERNAL_REFERENCE_PREFIX = "entra-device:"

IDENTITY_CATEGORY = "IDENTITY"
USER_ACCOUNT = "USER_ACCOUNT"

LINK_LOGGED_ON = "LOGGED_ON"
LINK_USES = "USES"

# Statuses an OpenAEV answers for a field, a category or a route it does not
# have: the feature is unavailable on that platform, not a transient failure.
UNSUPPORTED_STATUSES = {400, 404, 405, 422, 501}

# Counter keys, logged in the run summary.
IDENTITIES_UPSERTED = "identities_upserted"
IDENTITIES_SKIPPED = "identities_skipped"
IDENTITIES_FAILED = "identities_failed"
IDENTITIES_UNAVAILABLE = "identities_unavailable"
DEVICES_UPSERTED = "devices_upserted"
DEVICES_FAILED = "devices_failed"
LINKS_WRITTEN = "links_written"
LINKS_ALREADY_WRITTEN = "links_already_written"
LINKS_SKIPPED = "links_skipped"
LINKS_FAILED = "links_failed"
LINKS_UNAVAILABLE = "links_unavailable"

LINKS_UNAVAILABLE_MESSAGE = (
    "asset links not available on this OpenAEV, skipped (they need a version "
    "with the asset links API and the EXPLORATION_GRAPH preview feature on)"
)


def identity_external_reference(object_id: str) -> str:
    """The external reference of the identity asset of an Entra user."""
    return f"{IDENTITY_EXTERNAL_REFERENCE_PREFIX}{object_id}"


def device_external_reference(device_id: str) -> str:
    """The external reference of an Entra device Intune does not manage."""
    return f"{DEVICE_EXTERNAL_REFERENCE_PREFIX}{device_id}"


def _status(error: Exception) -> int | None:
    return getattr(error, "response_code", None)


def _asset_id(result: Any) -> str | None:
    if isinstance(result, dict):
        return result.get("asset_id")
    return None


class AssetWriter:
    """Writes identity assets, endpoints carrying optional fields and asset links.

    The links this process wrote (or found) are remembered across runs, so a
    link removed by hand in OpenAEV is not written again on every run (it is
    written again once after a collector restart).
    """

    def __init__(self, api: Any, logger: Any) -> None:
        self.api = api
        self.logger = logger
        self.counts: Counter[str] = Counter()
        self._known_links: set[tuple[str, str, str]] = set()
        self._dropped_fields: set[str] = set()
        self.start_run()

    def start_run(self) -> None:
        """Reset the per-run counts and capability reads."""
        self.counts = Counter()
        self._identities_available = True
        self._links_available: bool | None = None
        self._dropped_fields = set()

    # -- endpoints and identities -------------------------------------------

    def upsert_endpoint(
        self, endpoint: dict[str, Any], optional_fields: tuple[str, ...] = ()
    ) -> str | None:
        """Upsert an endpoint and return its asset id.

        A field of optional_fields that the platform refuses (400 or 422) is
        dropped for the rest of the run and the upsert is sent again without
        it. Any other error propagates to the caller.
        """
        payload = {
            key: value
            for key, value in endpoint.items()
            if key not in self._dropped_fields
        }
        try:
            return _asset_id(self.api.endpoint.upsert(payload))
        except Exception as error:
            sent_optional = [field for field in optional_fields if field in payload]
            if not sent_optional or _status(error) not in (400, 422):
                raise
            for field in sent_optional:
                payload.pop(field)
            result = self.api.endpoint.upsert(payload)
            # The upsert passed without them: this platform does not take them.
            self._dropped_fields.update(sent_optional)
            self.logger.warning(
                "OpenAEV refused the field(s) "
                f"{', '.join(sent_optional)} ({error}); they are left out for "
                "the rest of this run."
            )
            return _asset_id(result)

    def upsert_identity(
        self,
        object_id: str | None,
        user_principal_name: str | None,
        tag_ids: list[str] | None = None,
        linked_person: str | None = None,
        subcategory: str = USER_ACCOUNT,
    ) -> str | None:
        """Upsert the IDENTITY asset of an Entra user and return its asset id.

        The person link is sent only when known; leaving it out keeps the link
        another run (or another collector) wrote.
        """
        if not self._identities_available:
            self.counts[IDENTITIES_UNAVAILABLE] += 1
            return None
        if not object_id or not user_principal_name:
            self.counts[IDENTITIES_SKIPPED] += 1
            return None
        identity: dict[str, Any] = {
            "asset_name": user_principal_name,
            "asset_external_reference": identity_external_reference(object_id),
            "asset_category": IDENTITY_CATEGORY,
            "asset_subcategory": subcategory,
        }
        if tag_ids:
            identity["asset_tags"] = list(tag_ids)
        if linked_person:
            identity["asset_linked_person"] = linked_person
        try:
            asset_id = self.upsert_endpoint(identity, ("asset_linked_person",))
        except Exception as error:
            if _status(error) in UNSUPPORTED_STATUSES:
                # The platform does not know the IDENTITY category (or the
                # subcategory): no identity can be written in this run.
                self._identities_available = False
                self.counts[IDENTITIES_UNAVAILABLE] += 1
                self.logger.warning(
                    "Identity assets are not supported by this OpenAEV "
                    f"({error}); identities skipped for this run, everything "
                    "else is imported as usual."
                )
            else:
                self.counts[IDENTITIES_FAILED] += 1
                self.logger.warning(
                    f"Failed to upsert the identity {user_principal_name}: {error}"
                )
            return None
        self.counts[IDENTITIES_UPSERTED] += 1
        return asset_id

    # -- asset links ----------------------------------------------------------

    def links_available(self, asset_id: str) -> bool:
        """Probe once per run whether the platform exposes the asset links API.

        The probe reads the links of an asset the run just upserted, so a 404
        means the route is missing or the preview feature is off.
        """
        if self._links_available is None:
            try:
                self.api.http_get(f"/assets/{asset_id}/links")
                self._links_available = True
            except Exception as error:
                if _status(error) in UNSUPPORTED_STATUSES:
                    self._links_available = False
                    self.logger.info(LINKS_UNAVAILABLE_MESSAGE)
                else:
                    # Transient: probe again at the next link of this run.
                    self.logger.warning(f"Could not read the asset links: {error}")
                    return False
        return self._links_available

    def link(
        self, source_id: str | None, target_id: str | None, link_type: str
    ) -> None:
        """Link source to target (source -> target), once per process."""
        if not source_id or not target_id:
            self.counts[LINKS_SKIPPED] += 1
            return
        key = (source_id, target_id, link_type)
        if key in self._known_links:
            self.counts[LINKS_ALREADY_WRITTEN] += 1
            return
        if not self.links_available(source_id):
            self.counts[LINKS_UNAVAILABLE] += 1
            return
        try:
            # Adding a link that exists returns it unchanged.
            self.api.http_post(
                f"/assets/{source_id}/links",
                post_data={"linked_asset_id": target_id, "asset_link_type": link_type},
            )
        except Exception as error:
            self.counts[LINKS_FAILED] += 1
            self.logger.warning(
                f"Failed to link asset {source_id} to {target_id} ({link_type}): {error}"
            )
            return
        self._known_links.add(key)
        self.counts[LINKS_WRITTEN] += 1

    # -- owners ---------------------------------------------------------------

    def owner_links(self, *_args: Any, **_kwargs: Any) -> None:
        """Extension point for OWNED_BY / MANAGED_BY owner links.

        OpenAEV has no owner link type yet (item asset-ownership-links): this
        writes nothing until the platform exposes it.
        """
        return None

    # -- summary --------------------------------------------------------------

    def summary(self) -> str:
        """One line with the count of each outcome of the run."""
        counts = self.counts
        return (
            f"identities: {counts[IDENTITIES_UPSERTED]} upserted, "
            f"{counts[IDENTITIES_SKIPPED]} skipped, "
            f"{counts[IDENTITIES_FAILED]} failed, "
            f"{counts[IDENTITIES_UNAVAILABLE]} unavailable; "
            f"devices: {counts[DEVICES_UPSERTED]} upserted, "
            f"{counts[DEVICES_FAILED]} failed; "
            f"links: {counts[LINKS_WRITTEN]} written, "
            f"{counts[LINKS_ALREADY_WRITTEN]} already written, "
            f"{counts[LINKS_SKIPPED]} skipped, "
            f"{counts[LINKS_FAILED]} failed, "
            f"{counts[LINKS_UNAVAILABLE]} unavailable"
        )
