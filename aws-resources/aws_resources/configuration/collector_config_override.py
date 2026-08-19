from datetime import timedelta
from enum import StrEnum

from pydantic import Field, field_validator, model_validator
from pyoaev.configuration import ConfigLoaderCollector


class AWSAuthType(StrEnum):
    """The AWS authentication modes supported by the collector.

    - ``CREDENTIAL_PROVIDER_CHAIN``: legacy/default behavior, delegates
      credential resolution entirely to boto3 (environment, shared config,
      EC2/ECS instance role, ...).
    - ``CREDENTIALS``: explicit static credentials (access key + secret key,
      with an optional session token).
    - ``ROLES_ANYWHERE``: derive temporary credentials from an X.509 client
      certificate through IAM Roles Anywhere.
    """

    CREDENTIAL_PROVIDER_CHAIN = "credential_provider_chain"
    CREDENTIALS = "credentials"
    ROLES_ANYWHERE = "roles_anywhere"


# Kept for backward-compatible imports elsewhere in the codebase.
AUTH_TYPE_CREDENTIAL_PROVIDER_CHAIN = AWSAuthType.CREDENTIAL_PROVIDER_CHAIN
AUTH_TYPE_CREDENTIALS = AWSAuthType.CREDENTIALS
AUTH_TYPE_ROLES_ANYWHERE = AWSAuthType.ROLES_ANYWHERE


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
    aws_auth_type: AWSAuthType = Field(
        default=AWSAuthType.CREDENTIAL_PROVIDER_CHAIN,
        description=(
            "Authentication mode: 'credential_provider_chain' to let boto3 resolve "
            "credentials on its own (environment, shared config, instance role, "
            "...), 'credentials' for explicit static access key/secret, or "
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
    aws_roles_anywhere_trust_anchor_arn: str | None = Field(
        default=None,
        description="IAM Roles Anywhere trust anchor ARN (required for 'roles_anywhere')",
    )
    aws_roles_anywhere_profile_arn: str | None = Field(
        default=None,
        description="IAM Roles Anywhere profile ARN (required for 'roles_anywhere')",
    )
    aws_roles_anywhere_role_arn: str | None = Field(
        default=None,
        description="ARN of the IAM role to assume through IAM Roles Anywhere "
        "(required for 'roles_anywhere')",
    )
    aws_roles_anywhere_certificate: str | None = Field(
        default=None,
        description="PEM-encoded X.509 client certificate (required for 'roles_anywhere')",
    )
    aws_roles_anywhere_private_key: str | None = Field(
        default=None,
        description="PEM-encoded private key matching the client certificate "
        "(required for 'roles_anywhere')",
    )
    aws_roles_anywhere_certificate_chain: str | None = Field(
        default=None,
        description="Optional PEM-encoded intermediate certificate chain",
    )
    aws_roles_anywhere_private_key_passphrase: str | None = Field(
        default=None,
        description="Optional passphrase protecting the private key",
    )
    aws_roles_anywhere_region: str | None = Field(
        default=None,
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
        """Normalize the aws auth type to lowercase"""
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @model_validator(mode="after")
    def _validate_auth_type(self) -> "CollectorConfigOverride":
        """Ensure the settings required by the selected auth mode are present."""
        required_by_auth_type = {
            AWSAuthType.CREDENTIALS: (
                "aws_access_key_id",
                "aws_secret_access_key",
            ),
            AWSAuthType.ROLES_ANYWHERE: (
                "aws_roles_anywhere_trust_anchor_arn",
                "aws_roles_anywhere_profile_arn",
                "aws_roles_anywhere_role_arn",
                "aws_roles_anywhere_certificate",
                "aws_roles_anywhere_private_key",
            ),
        }
        required = required_by_auth_type.get(self.aws_auth_type, ())
        missing = [name for name in required if not (getattr(self, name) or "").strip()]
        if missing:
            raise ValueError(
                "the following settings are required when aws_auth_type is "
                f"'{self.aws_auth_type}': {', '.join(missing)}"
            )

        return self
