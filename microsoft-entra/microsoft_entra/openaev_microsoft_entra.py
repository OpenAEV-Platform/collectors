import asyncio

import requests
from azure.identity.aio import ClientSecretCredential
from microsoft_entra.configuration.config_loader import ConfigLoader
from msgraph import GraphServiceClient
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon


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

    async def create_users(self, graph_client, group_id, openaev_team):
        # Define tag colors
        tag_colors = {
            "source": "#ef4444",  # Red
            "user-type": "#10b981",  # Green
            "department": "#8b5cf6",  # Purple
            "job-title": "#f59e0b",  # Amber
        }

        members = await graph_client.groups.by_group_id(group_id).members.get()
        if members:
            for i in range(len(members.value)):
                # Skip non-user objects (like Device objects)
                member = members.value[i]
                if (
                    not hasattr(member, "mail")
                    or member.odata_type != "#microsoft.graph.user"
                ):
                    continue

                if member.mail is not None and (
                    self.include_external is True
                    or (
                        self.include_external is False
                        and "#EXT#" not in member.user_principal_name
                    )
                ):
                    # Prepare tag IDs list
                    tag_ids = []

                    # Add collector source tag
                    source_tag_name = "source:microsoft-entra"
                    source_tag_id = self._create_or_get_tag(
                        source_tag_name, tag_colors["source"]
                    )
                    if source_tag_id:
                        tag_ids.append(source_tag_id)

                    # Add external user tag if applicable
                    if "#EXT#" in member.user_principal_name:
                        ext_tag_name = "user-type:external"
                        ext_tag_id = self._create_or_get_tag(
                            ext_tag_name, tag_colors["user-type"]
                        )
                        if ext_tag_id:
                            tag_ids.append(ext_tag_id)
                    else:
                        int_tag_name = "user-type:internal"
                        int_tag_id = self._create_or_get_tag(
                            int_tag_name, tag_colors["user-type"]
                        )
                        if int_tag_id:
                            tag_ids.append(int_tag_id)

                    # Add department tag if available
                    if hasattr(member, "department") and member.department:
                        dept_tag_name = f"department:{member.department.lower()}"
                        dept_tag_id = self._create_or_get_tag(
                            dept_tag_name, tag_colors["department"]
                        )
                        if dept_tag_id:
                            tag_ids.append(dept_tag_id)

                    # Add job title tag if available
                    if hasattr(member, "job_title") and member.job_title:
                        job_tag_name = f"job-title:{member.job_title.lower()}"
                        job_tag_id = self._create_or_get_tag(
                            job_tag_name, tag_colors["job-title"]
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

        # iterate over result batches > 100 rows
        while members is not None and members.odata_next_link is not None:
            members = (
                await graph_client.groups.by_group_id(group_id)
                .members.with_url(members.odata_next_link)
                .get()
            )
            if members:
                for i in range(len(members.value)):
                    # Skip non-user objects (like Device objects)
                    member = members.value[i]
                    if (
                        not hasattr(member, "mail")
                        or member.odata_type != "#microsoft.graph.user"
                    ):
                        continue

                    if member.mail is not None and (
                        self.include_external is True
                        or (
                            self.include_external is False
                            and "#EXT#" not in member.user_principal_name
                        )
                    ):
                        # Prepare tag IDs list
                        tag_ids = []

                        # Add collector source tag
                        source_tag_name = "source:microsoft-entra"
                        source_tag_id = self._create_or_get_tag(
                            source_tag_name, tag_colors["source"]
                        )
                        if source_tag_id:
                            tag_ids.append(source_tag_id)

                        # Add external user tag if applicable
                        if "#EXT#" in member.user_principal_name:
                            ext_tag_name = "user-type:external"
                            ext_tag_id = self._create_or_get_tag(
                                ext_tag_name, tag_colors["user-type"]
                            )
                            if ext_tag_id:
                                tag_ids.append(ext_tag_id)
                        else:
                            int_tag_name = "user-type:internal"
                            int_tag_id = self._create_or_get_tag(
                                int_tag_name, tag_colors["user-type"]
                            )
                            if int_tag_id:
                                tag_ids.append(int_tag_id)

                        # Add department tag if available
                        if hasattr(member, "department") and member.department:
                            dept_tag_name = f"department:{member.department.lower()}"
                            dept_tag_id = self._create_or_get_tag(
                                dept_tag_name, tag_colors["department"]
                            )
                            if dept_tag_id:
                                tag_ids.append(dept_tag_id)

                        # Add job title tag if available
                        if hasattr(member, "job_title") and member.job_title:
                            job_tag_name = f"job-title:{member.job_title.lower()}"
                            job_tag_id = self._create_or_get_tag(
                                job_tag_name, tag_colors["job-title"]
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

    async def create_groups(self, graph_client):
        groups = await graph_client.groups.get()
        if groups:
            for i in range(len(groups.value)):
                team = {"team_name": groups.value[i].display_name}
                openaev_team = self.api.team.upsert(team)
                await self.create_users(graph_client, groups.value[i].id, openaev_team)
        # iterate over result batches > 100 rows
        while groups is not None and groups.odata_next_link is not None:
            groups = await graph_client.groups.with_url(groups.odata_next_link)
            if groups:
                for i in range(len(groups.value)):
                    team = {"team_name": groups.value[i].display_name}
                    openaev_team = self.api.team.upsert(team)
                    await self.create_users(
                        graph_client, groups.value[i].id, openaev_team
                    )

    def _process_message(self) -> None:
        # Auth
        scopes = ["https://graph.microsoft.com/.default"]
        credential = ClientSecretCredential(
            tenant_id=self._configuration.get("microsoft_entra_tenant_id"),
            client_id=self._configuration.get("microsoft_entra_client_id"),
            client_secret=self._configuration.get("microsoft_entra_client_secret"),
        )
        graph_client = GraphServiceClient(credential, scopes)  # type: ignore

        # Execute
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.create_groups(graph_client))


if __name__ == "__main__":
    OpenAEVMicrosoftEntra(configuration=ConfigLoader().to_daemon_config()).start()
