import asyncio
import os

import requests
from azure.identity.aio import CertificateCredential, ClientSecretCredential
from microsoft_entra.configuration.config_loader import ConfigLoader
from msgraph import GraphServiceClient
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

TAG_COLORS = {
    "source": "#ef4444",  # Red
    "user-type": "#10b981",  # Green
    "department": "#8b5cf6",  # Purple
    "job-title": "#f59e0b",  # Amber
}


class OpenAEVMicrosoftEntra(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_microsoft_entra",
        )
        self.session = requests.Session()

        # External
        self.include_external = self._configuration.get("include_external")

    def _create_or_get_tag(self, tag_name, tag_color="#6b7280"):
        """Create or get a tag and return its ID."""
        try:
            tag_data = {"tag_name": tag_name, "tag_color": tag_color}
            result = self.api.tag.upsert(tag_data)
            return result.get("tag_id")
        except Exception as e:
            self.logger.warning(f"Failed to upsert tag {tag_name}: {e}")
            return None

    def _upsert_member(self, member, openaev_team):
        """Upsert one group member as an OpenAEV user of the team."""
        # Skip non-user objects (like Device objects)
        if not hasattr(member, "mail") or member.odata_type != "#microsoft.graph.user":
            return

        if member.mail is None or not (
            self.include_external is True
            or (
                self.include_external is False
                and "#EXT#" not in member.user_principal_name
            )
        ):
            return

        # Prepare tag IDs list
        tag_ids = []

        # Add collector source tag
        source_tag_id = self._create_or_get_tag(
            "source:microsoft-entra", TAG_COLORS["source"]
        )
        if source_tag_id:
            tag_ids.append(source_tag_id)

        # Add external or internal user tag
        if "#EXT#" in member.user_principal_name:
            user_type_tag_name = "user-type:external"
        else:
            user_type_tag_name = "user-type:internal"
        user_type_tag_id = self._create_or_get_tag(
            user_type_tag_name, TAG_COLORS["user-type"]
        )
        if user_type_tag_id:
            tag_ids.append(user_type_tag_id)

        # Add department tag if available
        if hasattr(member, "department") and member.department:
            dept_tag_id = self._create_or_get_tag(
                f"department:{member.department.lower()}", TAG_COLORS["department"]
            )
            if dept_tag_id:
                tag_ids.append(dept_tag_id)

        # Add job title tag if available
        if hasattr(member, "job_title") and member.job_title:
            job_tag_id = self._create_or_get_tag(
                f"job-title:{member.job_title.lower()}", TAG_COLORS["job-title"]
            )
            if job_tag_id:
                tag_ids.append(job_tag_id)

        user = {
            "user_email": member.mail,
            "user_firstname": member.given_name,
            "user_lastname": member.surname,
            "user_teams": [openaev_team["team_id"]],
        }

        # Add tags if we have any
        if tag_ids:
            user["user_tags"] = tag_ids

        self.api.user.upsert(user)

    async def create_users(self, graph_client, group_id, openaev_team):
        members_builder = graph_client.groups.by_group_id(group_id).members
        members = await members_builder.get()
        # Graph returns results in pages (100 rows by default): the first page
        # and every next page go through the same handler.
        while members is not None:
            for member in members.value or []:
                self._upsert_member(member, openaev_team)
            if members.odata_next_link is None:
                break
            members = await members_builder.with_url(members.odata_next_link).get()

    async def create_groups(self, graph_client):
        groups = await graph_client.groups.get()
        # Graph returns results in pages (100 rows by default): the first page
        # and every next page go through the same handler.
        while groups is not None:
            for group in groups.value or []:
                team = {"team_name": group.display_name}
                openaev_team = self.api.team.upsert(team)
                await self.create_users(graph_client, group.id, openaev_team)
            if groups.odata_next_link is None:
                break
            groups = await graph_client.groups.with_url(groups.odata_next_link).get()

    def _process_message(self) -> None:
        # Auth
        scopes = ["https://graph.microsoft.com/.default"]
        use_certificate_auth = bool(
            self._configuration.get("microsoft_entra_use_certificate_auth")
        )

        if use_certificate_auth:
            certificate_data = self._configuration.get(
                "microsoft_entra_client_cert_data"
            )
            thumbprint = self._configuration.get(
                "microsoft_entra_client_cert_thumbprint"
            )
            passphrase = self._configuration.get(
                "microsoft_entra_client_cert_passphrase"
            )

            credential_kwargs = {
                "tenant_id": self._configuration.get("microsoft_entra_tenant_id"),
                "client_id": self._configuration.get("microsoft_entra_client_id"),
                "certificate_data": certificate_data.encode("utf-8"),
                "thumbprint": thumbprint,
            }
            if passphrase:
                credential_kwargs["password"] = passphrase.encode("utf-8")

            credential = CertificateCredential(**credential_kwargs)
        else:
            credential = ClientSecretCredential(
                tenant_id=self._configuration.get("microsoft_entra_tenant_id"),
                client_id=self._configuration.get("microsoft_entra_client_id"),
                client_secret=self._configuration.get("microsoft_entra_client_secret"),
            )

        graph_client = GraphServiceClient(credential, scopes)  # type: ignore

        # Execute
        asyncio.run(self.create_groups(graph_client))


def main():
    for key in [
        "MICROSOFT_ENTRA_TENANT_ID",
        "MICROSOFT_ENTRA_CLIENT_ID",
        "MICROSOFT_ENTRA_CLIENT_SECRET",
        "INCLUDE_EXTERNAL",
    ]:
        if not os.environ.get(f"COLLECTOR_{key}") and os.environ.get(key):
            os.environ[f"COLLECTOR_{key}"] = os.environ.get(key)

    OpenAEVMicrosoftEntra(configuration=ConfigLoader().to_daemon_config()).start()
