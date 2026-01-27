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
        description="JSON string containing service account credentials",
    )
    google_workspace_delegated_admin_email: str = Field(
        description="Email of the admin user for domain-wide delegation",
    )
    google_workspace_customer_id: str = Field(
        description="Google Workspace customer ID or 'my_customer' for your own domain",
    )
    include_suspended: bool = Field(
        description="Whether to include suspended users in synchronization",
    )
    sync_all_users: bool = Field(
        description="If true, sync all users; if false, only sync users who are group members",
    )
