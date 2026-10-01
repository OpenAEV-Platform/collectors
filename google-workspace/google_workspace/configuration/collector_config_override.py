from datetime import timedelta

from pydantic import Field, model_validator
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Google Workspace",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="google_workspace/img/icon-google-workspace.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    google_workspace_auth_type: str = Field(
        default="service_account_json",
        description=(
            "Authentication mode: 'service_account_json' (default) uses the "
            "downloaded service account JSON key, 'certificate' signs the "
            "OAuth2 JWT-bearer assertion directly with a private key/"
            "certificate pair the operator generates and registers "
            "themselves, without ever handing the key material to Google."
        ),
    )
    google_workspace_service_account_json: str | None = Field(
        default=None,
        description=(
            "JSON string containing service account credentials. Required "
            "when google_workspace_auth_type is 'service_account_json'."
        ),
    )
    google_workspace_client_email: str | None = Field(
        default=None,
        description=(
            "Service account client email. Required when "
            "google_workspace_auth_type is 'certificate'."
        ),
    )
    google_workspace_client_certificate: str | None = Field(
        default=None,
        description=(
            "PEM-encoded X.509 certificate registered as the service "
            "account's external public key. Required when "
            "google_workspace_auth_type is 'certificate'."
        ),
    )
    google_workspace_client_private_key: str | None = Field(
        default=None,
        description=(
            "PEM-encoded private key matching google_workspace_client_certificate, "
            "used to sign the JWT-bearer assertion. Required when "
            "google_workspace_auth_type is 'certificate'."
        ),
    )
    google_workspace_client_private_key_id: str | None = Field(
        default=None,
        description=(
            "Optional key identifier ('kid') for the registered certificate, "
            "if Google assigned one when the external key was uploaded."
        ),
    )
    google_workspace_token_uri: str = Field(
        default="https://oauth2.googleapis.com/token",
        description=(
            "OAuth2 token endpoint used to exchange the signed JWT assertion "
            "for an access token. Override to point at a private mTLS-enabled "
            "endpoint or a test double."
        ),
    )
    google_workspace_delegated_admin_email: str = Field(
        description="Email of the admin user for domain-wide delegation",
    )
    google_workspace_customer_id: str = Field(
        default="my_customer",
        description="Google Workspace customer ID or 'my_customer' for your own domain",
    )
    include_suspended: bool = Field(
        default=False,
        description="Whether to include suspended users in synchronization",
    )
    sync_all_users: bool = Field(
        default=False,
        description="If true, sync all users; if false, only sync users who are group members",
    )

    @model_validator(mode="after")
    def _validate_auth_material(self) -> "CollectorConfigOverride":
        auth_type = (self.google_workspace_auth_type or "service_account_json").lower()
        if auth_type == "certificate":
            missing = [
                name
                for name, value in (
                    (
                        "google_workspace_client_email",
                        self.google_workspace_client_email,
                    ),
                    (
                        "google_workspace_client_certificate",
                        self.google_workspace_client_certificate,
                    ),
                    (
                        "google_workspace_client_private_key",
                        self.google_workspace_client_private_key,
                    ),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "google_workspace_auth_type is 'certificate' but the "
                    f"following fields are missing: {', '.join(missing)}"
                )
        elif auth_type == "service_account_json":
            if not self.google_workspace_service_account_json:
                raise ValueError(
                    "google_workspace_service_account_json is required when "
                    "google_workspace_auth_type is 'service_account_json'"
                )
        else:
            raise ValueError(
                "google_workspace_auth_type must be either 'service_account_json' "
                f"or 'certificate', got {auth_type!r}"
            )
        return self
