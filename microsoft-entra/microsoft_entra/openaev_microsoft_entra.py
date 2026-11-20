import asyncio
import os
from collections import Counter

import requests
from azure.identity.aio import CertificateCredential, ClientSecretCredential
from kiota_abstractions.base_request_configuration import RequestConfiguration
from microsoft_entra.configuration.config_loader import ConfigLoader
from msgraph import GraphServiceClient
from msgraph.generated.groups.item.members.members_request_builder import (
    MembersRequestBuilder,
)
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

TAG_COLORS = {
    "source": "#ef4444",  # Red
    "user-type": "#10b981",  # Green
    "department": "#8b5cf6",  # Purple
    "job-title": "#f59e0b",  # Amber
}

# Graph returns a default property set for group members, and department is
# not in it: ask for every property the collector reads.
MEMBER_SELECT = [
    "id",
    "mail",
    "userPrincipalName",
    "givenName",
    "surname",
    "jobTitle",
    "department",
    "userType",
]

# Outcome of one group member, counted per run and logged at its end.
UPSERTED = "upserted"
SKIPPED_NOT_USER = "skipped_not_user"
SKIPPED_NO_MAIL = "skipped_no_mail"
SKIPPED_EXTERNAL = "skipped_external"


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
        """Upsert one group member as an OpenAEV user of the team.

        Returns the member's outcome (UPSERTED or a SKIPPED_* reason), counted
        per run so a run that filtered every member can be told from one that
        aborted.
        """
        # Skip non-user objects (like Device objects)
        if (
            not hasattr(member, "mail")
            or getattr(member, "odata_type", None) != "#microsoft.graph.user"
        ):
            return SKIPPED_NOT_USER

        # Graph returns a user without mail when it has no mailbox, or when the
        # app lacks User.Read.All / Directory.Read.All (limited information).
        if member.mail is None:
            return SKIPPED_NO_MAIL

        if self.include_external is not True and "#EXT#" in (
            member.user_principal_name or ""
        ):
            return SKIPPED_EXTERNAL

        # Prepare tag IDs list
        tag_ids = []

        # Add collector source tag
        source_tag_id = self._create_or_get_tag(
            "source:microsoft-entra", TAG_COLORS["source"]
        )
        if source_tag_id:
            tag_ids.append(source_tag_id)

        # Add external or internal user tag
        if "#EXT#" in (member.user_principal_name or ""):
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
        return UPSERTED

    async def create_users(self, graph_client, group_id, openaev_team):
        """Upsert the direct members of a group (nested groups are not
        expanded) and return the count of each member outcome."""
        outcomes = Counter()
        members_builder = graph_client.groups.by_group_id(group_id).members
        request_configuration = RequestConfiguration(
            query_parameters=MembersRequestBuilder.MembersRequestBuilderGetQueryParameters(
                select=MEMBER_SELECT
            )
        )
        members = await members_builder.get(request_configuration=request_configuration)
        # Graph returns results in pages (100 rows by default): the first page
        # and every next page go through the same handler. The next link keeps
        # the $select of the first request.
        while members is not None:
            for member in members.value or []:
                outcomes[self._upsert_member(member, openaev_team)] += 1
            if members.odata_next_link is None:
                break
            members = await members_builder.with_url(members.odata_next_link).get()
        return outcomes

    async def create_groups(self, graph_client):
        """Upsert every group as a team with its members and return the count
        of groups and of each member outcome."""
        totals = Counter()
        groups = await graph_client.groups.get()
        # Graph returns results in pages (100 rows by default): the first page
        # and every next page go through the same handler.
        while groups is not None:
            for group in groups.value or []:
                team = {"team_name": group.display_name}
                openaev_team = self.api.team.upsert(team)
                totals["groups"] += 1
                outcomes = await self.create_users(graph_client, group.id, openaev_team)
                if isinstance(outcomes, Counter):
                    totals.update(outcomes)
            if groups.odata_next_link is None:
                break
            groups = await graph_client.groups.with_url(groups.odata_next_link).get()
        return totals

    def _log_run_summary(self, totals):
        """Log the end-of-run counts, and warn when every user member came
        back without mail, the sign of a missing Graph permission."""
        self.logger.info(
            "Microsoft Entra run done: "
            f"{totals['groups']} group(s), "
            f"{totals[UPSERTED]} member(s) upserted, skipped: "
            f"{totals[SKIPPED_NO_MAIL]} without mail, "
            f"{totals[SKIPPED_EXTERNAL]} external, "
            f"{totals[SKIPPED_NOT_USER]} not a user "
            "(direct members only, nested groups are not expanded)"
        )
        if totals[SKIPPED_NO_MAIL] and not totals[UPSERTED]:
            self.logger.warning(
                f"Microsoft Entra: all {totals[SKIPPED_NO_MAIL]} user member(s) "
                "came back without mail, so no player was imported. Check that "
                "the app registration holds the User.Read.All or "
                "Directory.Read.All application permission with admin consent."
            )

    async def _collect(self, credential, graph_client):
        # The async credential owns an aiohttp session (its token transport):
        # close it on the run's event loop, also when the run fails, so asyncio
        # does not report an "Unclosed client session" when the loop ends.
        async with credential:
            totals = await self.create_groups(graph_client)
        if isinstance(totals, Counter):
            self._log_run_summary(totals)

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
        asyncio.run(self._collect(credential, graph_client))


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
