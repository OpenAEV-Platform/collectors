from datetime import timedelta

from pydantic import Field, field_validator, model_validator
from pyoaev.configuration import ConfigLoaderCollector

AUTH_TYPE_CREDENTIALS = "credentials"
AUTH_TYPE_ROLES_ANYWHERE = "roles_anywhere"
AUTH_TYPES = (AUTH_TYPE_CREDENTIALS, AUTH_TYPE_ROLES_ANYWHERE)


def normalize_auth_type(value: object) -> object:
    """Normalize an auth type, falling back to the default when unset.

    Non-string values are returned untouched so that pydantic reports the type
    error itself. Unknown modes raise, to fail fast on a typo rather than
    silently falling back to credentials.
    """
    if value is None:
        return AUTH_TYPE_CREDENTIALS
    if not isinstance(value, str):
        return value

    normalized = value.strip().lower()
    if not normalized:
        return AUTH_TYPE_CREDENTIALS
    if normalized not in AUTH_TYPES:
        raise ValueError(
            f"aws_auth_type must be one of {', '.join(AUTH_TYPES)}, got '{value}'"
        )
    return normalized


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_aws_resources",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="AWS Resources",
        description="Collector display name",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    icon_filepath: str | None = Field(
        default="aws_resources/img/icon-aws-resources.png",
        description="Path to the icon file",
    )
    aws_auth_type: str = Field(
        default=AUTH_TYPE_CREDENTIALS,
        description=(
            "Authentication mode: 'credentials' for static/instance credentials, "
            "'roles_anywhere' to derive temporary credentials from an X.509 client "
            "certificate through IAM Roles Anywhere"
        ),
    )
    aws_access_key_id: str = Field(
        default="",
        description="AWS Access Key ID",
    )
    aws_secret_access_key: str = Field(
        default="",
        description="AWS Secret Access Key",
    )
    aws_session_token: str = Field(
        default="",
        description="AWS Session Token (for temporary credentials)",
    )
    aws_assume_role_arn: str = Field(
        default="",
        description="ARN of IAM role to assume",
    )
    aws_regions: str = Field(
        default="",
        description="Comma-separated list of AWS regions",
    )
    aws_roles_anywhere_trust_anchor_arn: str = Field(
        default="",
        description="IAM Roles Anywhere trust anchor ARN (required for 'roles_anywhere')",
    )
    aws_roles_anywhere_profile_arn: str = Field(
        default="",
        description="IAM Roles Anywhere profile ARN (required for 'roles_anywhere')",
    )
    aws_roles_anywhere_role_arn: str = Field(
        default="",
        description="ARN of the IAM role to assume through IAM Roles Anywhere "
        "(required for 'roles_anywhere')",
    )
    aws_roles_anywhere_certificate: str = Field(
        default="",
        description="PEM-encoded X.509 client certificate (required for 'roles_anywhere')",
    )
    aws_roles_anywhere_private_key: str = Field(
        default="",
        description="PEM-encoded private key matching the client certificate "
        "(required for 'roles_anywhere')",
    )
    aws_roles_anywhere_certificate_chain: str = Field(
        default="",
        description="Optional PEM-encoded intermediate certificate chain",
    )
    aws_roles_anywhere_private_key_passphrase: str = Field(
        default="",
        description="Optional passphrase protecting the private key",
    )
    aws_roles_anywhere_region: str = Field(
        default="",
        description="AWS region of the IAM Roles Anywhere endpoint. Derived from the "
        "trust anchor ARN when left empty",
    )
    aws_roles_anywhere_session_duration: int = Field(
        default=3600,
        ge=900,
        le=43200,
        description="Lifetime in seconds of the temporary credentials (900 to 43200)",
    )

    @field_validator("aws_auth_type", mode="before")
    @classmethod
    def _normalize_auth_type(cls, value: object) -> object:
        """Normalize the auth type and reject unknown modes."""
        return normalize_auth_type(value)

    @model_validator(mode="after")
    def _validate_auth_type(self) -> "CollectorConfigOverride":
        """Ensure the settings required by the selected auth mode are present."""
        if self.aws_auth_type == AUTH_TYPE_ROLES_ANYWHERE:
            missing = [
                name
                for name in (
                    "aws_roles_anywhere_trust_anchor_arn",
                    "aws_roles_anywhere_profile_arn",
                    "aws_roles_anywhere_role_arn",
                    "aws_roles_anywhere_certificate",
                    "aws_roles_anywhere_private_key",
                )
                if not (getattr(self, name) or "").strip()
            ]
            if missing:
                raise ValueError(
                    "the following settings are required when aws_auth_type is "
                    f"'{AUTH_TYPE_ROLES_ANYWHERE}': {', '.join(missing)}"
                )

        return self
