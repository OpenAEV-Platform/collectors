import re
from datetime import timedelta
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_ovhcloud",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="OVHcloud",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="ovhcloud/img/icon-ovhcloud.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )

    # -- API access ----------------------------------------------------------------------
    ovhcloud_endpoint: Literal["ovh-eu", "ovh-ca", "ovh-us"] = Field(
        default="ovh-eu",
        description="OVHcloud API endpoint: ovh-eu, ovh-ca or ovh-us.",
    )
    ovhcloud_application_key: SecretStr | None = Field(
        default=None,
        description="Application key (with the application secret and the consumer key).",
    )
    ovhcloud_application_secret: SecretStr | None = Field(
        default=None,
        description="Application secret (with the application key and the consumer key).",
    )
    ovhcloud_consumer_key: SecretStr | None = Field(
        default=None,
        description="Consumer key granted GET-only access rules (see README).",
    )
    ovhcloud_client_id: SecretStr | None = Field(
        default=None,
        description="OAuth2 service account client id (alternative to the application keys).",
    )
    ovhcloud_client_secret: SecretStr | None = Field(
        default=None,
        description="OAuth2 service account client secret (alternative to the application keys).",
    )

    # -- what to collect -------------------------------------------------------------------
    ovhcloud_collect_dedicated_servers: bool = Field(
        default=True,
        description="Collect dedicated servers (bare metal).",
    )
    ovhcloud_collect_public_cloud: bool = Field(
        default=False,
        description="Collect Public Cloud instances.",
    )
    ovhcloud_collect_vps: bool = Field(
        default=False,
        description="Collect VPS.",
    )
    ovhcloud_collect_hosted_private_cloud: bool = Field(
        default=False,
        description="Collect Hosted Private Cloud (VMware) virtual machines.",
    )

    # -- filters ---------------------------------------------------------------------------
    ovhcloud_public_cloud_project_ids: str | None = Field(
        default=None,
        description="Comma-separated Public Cloud project ids; empty for every project.",
    )
    ovhcloud_regions: str | None = Field(
        default=None,
        description="Comma-separated regions or datacenters to keep (e.g. GRA11,rbx,BHS5); "
        "empty for all.",
    )
    ovhcloud_name_include: str | None = Field(
        default=None,
        description="Regular expression: keep only the resources whose name, service name or "
        "hostname matches it.",
    )
    ovhcloud_name_exclude: str | None = Field(
        default=None,
        description="Regular expression: drop the resources whose name, service name or "
        "hostname matches it.",
    )
    ovhcloud_iam_tags: str | None = Field(
        default=None,
        description="Comma-separated key=value IAM tags a resource must all carry to be kept.",
    )
    ovhcloud_skip_inactive: bool = Field(
        default=True,
        description="Skip suspended, expired, deleted or errored resources.",
    )

    # -- IP addresses ----------------------------------------------------------------------
    ovhcloud_include_public_ipv4: bool = Field(
        default=True,
        description="Register public IPv4 addresses.",
    )
    ovhcloud_include_public_ipv6: bool = Field(
        default=True,
        description="Register public IPv6 addresses (single addresses; routed blocks go to "
        "the asset metadata).",
    )
    ovhcloud_include_private_ips: bool = Field(
        default=True,
        description="Register private addresses (vRack, private networks).",
    )

    # -- tagging and tuning ----------------------------------------------------------------
    ovhcloud_import_tags: bool = Field(
        default=True,
        description="Import the OVHcloud IAM tags of a resource as OpenAEV tags.",
    )
    ovhcloud_max_workers: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum concurrent detail calls to the OVHcloud API.",
    )

    @field_validator("ovhcloud_name_include", "ovhcloud_name_exclude")
    @classmethod
    def _validate_regex(cls, value: str | None) -> str | None:
        """Reject an invalid regular expression at start-up, not at the first run."""
        if not value:
            return None
        try:
            re.compile(value)
        except re.error as err:
            raise ValueError(f"invalid regular expression '{value}': {err}") from err
        return value

    @field_validator("ovhcloud_iam_tags")
    @classmethod
    def _validate_iam_tags(cls, value: str | None) -> str | None:
        """Require ``key=value`` items."""
        if not value:
            return None
        for item in value.split(","):
            item = item.strip()
            if item and ("=" not in item or not item.partition("=")[0].strip()):
                raise ValueError(
                    f"IAM tag filter '{item}' must be written key=value (several separated "
                    "by commas)"
                )
        return value

    @model_validator(mode="after")
    def _validate_credentials(self) -> Self:
        """Require one complete set of credentials."""
        application = [
            self.ovhcloud_application_key,
            self.ovhcloud_application_secret,
            self.ovhcloud_consumer_key,
        ]
        oauth2 = [self.ovhcloud_client_id, self.ovhcloud_client_secret]
        if all(oauth2) or all(application):
            return self
        raise ValueError(
            "OVHcloud credentials are incomplete: set ovhcloud_application_key, "
            "ovhcloud_application_secret and ovhcloud_consumer_key, or "
            "ovhcloud_client_id and ovhcloud_client_secret"
        )
