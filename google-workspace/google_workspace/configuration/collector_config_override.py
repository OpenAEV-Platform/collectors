from datetime import timedelta

from pydantic import Field
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
    google_workspace_service_account_json: str = Field(
        alias="GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON",
        description="JSON string containing service account credentials",
    )
    google_workspace_delegated_admin_email: str = Field(
        alias="GOOGLE_WORKSPACE_DELEGATED_ADMIN_EMAIL",
        description="Email of the admin user for domain-wide delegation",
    )
    google_workspace_customer_id: str = Field(
        alias="GOOGLE_WORKSPACE_CUSTOMER_ID",
        description="Google Workspace customer ID or 'my_customer' for your own domain",
    )
    include_suspended: bool = Field(
        alias="INCLUDE_SUSPENDED",
        description="Whether to include suspended users in synchronization",
    )
    sync_all_users: bool = Field(
        alias="SYNC_ALL_USERS",
        description="If true, sync all users; if false, only sync users who are group members",
    )
