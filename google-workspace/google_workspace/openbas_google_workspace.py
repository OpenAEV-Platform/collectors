import json
from typing import Any, Dict, List, Optional

import requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper


class OpenBASGoogleWorkspace:
    def __init__(self):
        self.session = requests.Session()
        self.config = OpenBASConfigHelper(
            __file__,
            {
                # API information
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                # Config information
                "collector_id": {
                    "env": "COLLECTOR_ID",
                    "file_path": ["collector", "id"],
                },
                "collector_name": {
                    "env": "COLLECTOR_NAME",
                    "file_path": ["collector", "name"],
                    "default": "Google Workspace",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                    "default": "warn",
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                    "is_number": True,
                    "default": 60,
                },
                "google_workspace_service_account_json": {
                    "env": "GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON",
                    "file_path": ["collector", "google_workspace_service_account_json"],
                },
                "google_workspace_delegated_admin_email": {
                    "env": "GOOGLE_WORKSPACE_DELEGATED_ADMIN_EMAIL",
                    "file_path": [
                        "collector",
                        "google_workspace_delegated_admin_email",
                    ],
                },
                "google_workspace_customer_id": {
                    "env": "GOOGLE_WORKSPACE_CUSTOMER_ID",
                    "file_path": ["collector", "google_workspace_customer_id"],
                    "default": "my_customer",  # Default value that works for most cases
                },
                "include_suspended": {
                    "env": "INCLUDE_SUSPENDED",
                    "file_path": ["collector", "include_suspended"],
                    "default": False,
                },
                "sync_all_users": {
                    "env": "SYNC_ALL_USERS",
                    "file_path": ["collector", "sync_all_users"],
                    "default": False,
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            config=self.config,
            icon="google_workspace/img/icon-google-workspace.png",
            collector_type="openbas_google_workspace",
        )

        # Configuration
        self.include_suspended = self.config.get_conf(
            "include_suspended", default=False
        )
        self.sync_all_users = self.config.get_conf("sync_all_users", default=False)
        self.customer_id = self.config.get_conf(
            "google_workspace_customer_id", default="my_customer"
        )

    def _create_or_get_tag(
        self, tag_name: str, tag_color: str = "#6b7280"
    ) -> Optional[str]:
        """Create or get a tag and return its ID."""
        try:
            tag_data = {"tag_name": tag_name, "tag_color": tag_color}
            result = self.helper.api.tag.upsert(tag_data)
            return result.get("tag_id")
        except Exception as e:
            self.helper.collector_logger.warning(
                f"Failed to upsert tag {tag_name}: {e}"
            )
            return None

    def _get_service(self) -> Any:
        """Initialize and return Google Admin SDK service."""
        # Parse service account JSON from environment or file
        service_account_json_str = self.config.get_conf(
            "google_workspace_service_account_json"
        )
        if not service_account_json_str:
            raise ValueError("Google Workspace service account JSON is required")

        # Parse JSON string if it's a string, otherwise assume it's already a dict
        if isinstance(service_account_json_str, str):
            service_account_info = json.loads(service_account_json_str)
        else:
            service_account_info = service_account_json_str

        # Create credentials with domain-wide delegation
        delegated_admin_email = self.config.get_conf(
            "google_workspace_delegated_admin_email"
        )
        if not delegated_admin_email:
            raise ValueError("Google Workspace delegated admin email is required")

        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=[
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "https://www.googleapis.com/auth/admin.directory.group.readonly",
                "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            ],
            subject=delegated_admin_email,
        )

        # Build the Admin SDK service
        service = build("admin", "directory_v1", credentials=credentials)
        return service

    def _get_all_users(self, service: Any) -> List[Dict[str, Any]]:
        """Retrieve all users from Google Workspace."""
        users = []
        page_token = None

        try:
            while True:
                # Build the query based on configuration
                query = None if self.include_suspended else "isSuspended=false"

                results = (
                    service.users()
                    .list(
                        customer=self.customer_id,
                        maxResults=500,
                        pageToken=page_token,
                        query=query,
                        orderBy="email",
                    )
                    .execute()
                )

                if "users" in results:
                    users.extend(results["users"])

                page_token = results.get("nextPageToken")
                if not page_token:
                    break

        except Exception as e:
            self.helper.collector_logger.error(f"Error fetching users: {e}")

        return users

    def _get_all_groups(self, service: Any) -> List[Dict[str, Any]]:
        """Retrieve all groups from Google Workspace."""
        groups = []
        page_token = None

        try:
            while True:
                results = (
                    service.groups()
                    .list(
                        customer=self.customer_id, maxResults=200, pageToken=page_token
                    )
                    .execute()
                )

                if "groups" in results:
                    groups.extend(results["groups"])

                page_token = results.get("nextPageToken")
                if not page_token:
                    break

        except Exception as e:
            self.helper.collector_logger.error(f"Error fetching groups: {e}")

        return groups

    def _get_group_members(self, service: Any, group_id: str) -> List[Dict[str, Any]]:
        """Retrieve all members of a specific group."""
        members = []
        page_token = None

        try:
            while True:
                results = (
                    service.members()
                    .list(groupKey=group_id, maxResults=200, pageToken=page_token)
                    .execute()
                )

                if "members" in results:
                    # Filter to only include USER type members
                    user_members = [
                        m for m in results["members"] if m.get("type") == "USER"
                    ]
                    members.extend(user_members)

                page_token = results.get("nextPageToken")
                if not page_token:
                    break

        except Exception as e:
            self.helper.collector_logger.warning(
                f"Error fetching members for group {group_id}: {e}"
            )

        return members

    def _create_user_with_tags(
        self, user: Dict[str, Any], team_ids: List[str] = None
    ) -> None:
        """Create or update a user in OpenBAS with appropriate tags."""
        # Define tag colors
        tag_colors = {
            "source": "#ef4444",  # Red
            "status": "#10b981",  # Green
            "org-unit": "#8b5cf6",  # Purple
            "role": "#f59e0b",  # Amber
        }

        # Skip users without primary email
        primary_email = user.get("primaryEmail")
        if not primary_email:
            return

        # Skip suspended users if configured
        if not self.include_suspended and user.get("suspended", False):
            return

        # Prepare tag IDs list
        tag_ids = []

        # Add collector source tag
        source_tag_name = "source:google-workspace"
        source_tag_id = self._create_or_get_tag(source_tag_name, tag_colors["source"])
        if source_tag_id:
            tag_ids.append(source_tag_id)

        # Add status tag (active/suspended)
        if user.get("suspended", False):
            status_tag_name = "status:suspended"
        else:
            status_tag_name = "status:active"
        status_tag_id = self._create_or_get_tag(status_tag_name, tag_colors["status"])
        if status_tag_id:
            tag_ids.append(status_tag_id)

        # Add organizational unit tag if available
        org_unit_path = user.get("orgUnitPath")
        if org_unit_path and org_unit_path != "/":
            # Clean up org unit path for tag name
            org_unit_clean = org_unit_path.strip("/").replace("/", "-").lower()
            org_tag_name = f"org-unit:{org_unit_clean}"
            org_tag_id = self._create_or_get_tag(org_tag_name, tag_colors["org-unit"])
            if org_tag_id:
                tag_ids.append(org_tag_id)

        # Add admin role tag if user is admin
        if user.get("isAdmin", False):
            admin_tag_name = "role:admin"
            admin_tag_id = self._create_or_get_tag(admin_tag_name, tag_colors["role"])
            if admin_tag_id:
                tag_ids.append(admin_tag_id)

        # Add delegated admin tag if user is delegated admin
        if user.get("isDelegatedAdmin", False):
            delegated_tag_name = "role:delegated-admin"
            delegated_tag_id = self._create_or_get_tag(
                delegated_tag_name, tag_colors["role"]
            )
            if delegated_tag_id:
                tag_ids.append(delegated_tag_id)

        # Extract name parts
        name = user.get("name", {})
        first_name = name.get("givenName", "")
        last_name = name.get("familyName", "")

        # If names are not available, try to extract from full name
        if not first_name and not last_name:
            full_name = name.get("fullName", "")
            if full_name:
                name_parts = full_name.split(" ", 1)
                first_name = name_parts[0] if name_parts else ""
                last_name = name_parts[1] if len(name_parts) > 1 else ""

        # Create user data
        user_data = {
            "user_email": primary_email,
            "user_firstname": first_name or "Unknown",
            "user_lastname": last_name or "User",
        }

        # Add teams if provided
        if team_ids:
            user_data["user_teams"] = team_ids

        # Add tags if we have any
        if tag_ids:
            user_data["user_tags"] = tag_ids

        # Upsert user to OpenBAS
        try:
            self.helper.api.user.upsert(user_data)
            self.helper.collector_logger.debug(f"Created/updated user: {primary_email}")
        except Exception as e:
            self.helper.collector_logger.error(
                f"Failed to upsert user {primary_email}: {e}"
            )

    def _sync_groups_and_members(self, service: Any) -> None:
        """Sync Google Workspace groups as teams and their members as users."""
        # Get all groups
        groups = self._get_all_groups(service)
        self.helper.collector_logger.info(
            f"Found {len(groups)} groups in Google Workspace"
        )

        # Process each group
        for group in groups:
            group_email = group.get("email")
            group_name = group.get("name", group_email)

            if not group_email:
                continue

            # Create or update team in OpenBAS
            team_data = {"team_name": group_name}
            try:
                openbas_team = self.helper.api.team.upsert(team_data)
                team_id = openbas_team.get("team_id")
                self.helper.collector_logger.debug(
                    f"Created/updated team: {group_name}"
                )

                # Get group members
                members = self._get_group_members(service, group_email)
                self.helper.collector_logger.debug(
                    f"Found {len(members)} members in group {group_name}"
                )

                # Process each member
                for member in members:
                    member_email = member.get("email")
                    if member_email:
                        # Get full user details
                        try:
                            user = service.users().get(userKey=member_email).execute()
                            self._create_user_with_tags(user, [team_id])
                        except Exception as e:
                            self.helper.collector_logger.warning(
                                f"Failed to get user details for {member_email}: {e}"
                            )

            except Exception as e:
                self.helper.collector_logger.error(
                    f"Failed to process group {group_name}: {e}"
                )

    def _sync_all_users(self, service: Any) -> None:
        """Sync all Google Workspace users without group associations."""
        users = self._get_all_users(service)
        self.helper.collector_logger.info(
            f"Found {len(users)} users in Google Workspace"
        )

        for user in users:
            self._create_user_with_tags(user)

    def _process_message(self) -> None:
        """Main processing method called by the collector daemon."""
        try:
            # Initialize Google Admin SDK service
            service = self._get_service()

            if self.sync_all_users:
                # Sync all users without group associations
                self.helper.collector_logger.info(
                    "Syncing all users from Google Workspace"
                )
                self._sync_all_users(service)
            else:
                # Sync groups and their members
                self.helper.collector_logger.info(
                    "Syncing groups and members from Google Workspace"
                )
                self._sync_groups_and_members(service)

            self.helper.collector_logger.info("Synchronization completed successfully")

        except Exception as e:
            self.helper.collector_logger.error(f"Error during synchronization: {e}")
            raise

    def start(self):
        """Start the collector daemon."""
        period = self.config.get_conf("collector_period", default=3600, is_number=True)
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASGoogleWorkspace = OpenBASGoogleWorkspace()
    openBASGoogleWorkspace.start()
