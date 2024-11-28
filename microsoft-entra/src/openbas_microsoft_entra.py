import asyncio

import requests
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper


class OpenBASMicrosoftEntra:
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
                },
                "collector_type": {
                    "env": "COLLECTOR_TYPE",
                    "file_path": ["collector", "type"],
                    "default": "openbas_microsoft_entra",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                },
                "microsoft_entra_tenant_id": {
                    "env": "MICROSOFT_ENTRA_TENANT_ID",
                    "file_path": ["collector", "microsoft_entra_tenant_id"],
                },
                "microsoft_entra_client_id": {
                    "env": "MICROSOFT_ENTRA_CLIENT_ID",
                    "file_path": ["collector", "microsoft_entra_client_id"],
                },
                "microsoft_entra_client_secret": {
                    "env": "MICROSOFT_ENTRA_CLIENT_SECRET",
                    "file_path": ["collector", "microsoft_entra_client_secret"],
                },
                "include_external": {
                    "env": "INCLUDE_EXTERNAL",
                    "file_path": ["collector", "include_external"],
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            config=self.config, icon="img/icon-microsoft-entra.png"
        )

        # External
        self.include_external = self.config.get_conf("include_external", default=False)

    async def create_users(self, graph_client, group_id, openbas_team):
        members = await graph_client.groups.by_group_id(group_id).members.get()
        if members:
            for i in range(len(members.value)):
                if members.value[i].mail is not None and (
                    self.include_external is True
                    or (
                        self.include_external is False
                        and "#EXT#" not in members.value[i].user_principal_name
                    )
                ):
                    user = {
                        "user_email": members.value[i].mail,
                        "user_firstname": members.value[i].given_name,
                        "user_lastname": members.value[i].surname,
                        "user_teams": [openbas_team["team_id"]],
                    }
                    self.helper.api.user.upsert(user)

        # iterate over result batches > 100 rows
        while members is not None and members.odata_next_link is not None:
            members = (
                await graph_client.groups.by_group_id(id)
                .members.with_url(members.odata_next_link)
                .get()
            )
            if members:
                for i in range(len(members.value)):
                    if members.value[i].mail is not None and (
                        self.include_external is True
                        or (
                            self.include_external is False
                            and "#EXT#" not in members.value[i].user_principal_name
                        )
                    ):
                        user = {
                            "user_email": members.value[i].mail,
                            "user_firstname": members.value[i].given_name,
                            "user_lastname": members.value[i].surname,
                            "user_teams": [openbas_team["team_id"]],
                        }
                        self.helper.api.user.upsert(user)

    async def create_groups(self, graph_client):
        groups = await graph_client.groups.get()
        if groups:
            for i in range(len(groups.value)):
                team = {"team_name": groups.value[i].display_name}
                openbas_team = self.helper.api.team.upsert(team)
                await self.create_users(graph_client, groups.value[i].id, openbas_team)
        # iterate over result batches > 100 rows
        while groups is not None and groups.odata_next_link is not None:
            groups = await graph_client.groups.with_url(groups.odata_next_link)
            if groups:
                for i in range(len(groups.value)):
                    team = {"team_name": groups.value[i].display_name}
                    openbas_team = self.helper.api.team.upsert(team)
                    await self.create_users(
                        graph_client, groups.value[i].id, openbas_team
                    )

    def _process_message(self) -> None:
        # Auth
        scopes = ["https://graph.microsoft.com/.default"]
        credential = ClientSecretCredential(
            tenant_id=self.config.get_conf("microsoft_entra_tenant_id"),
            client_id=self.config.get_conf("microsoft_entra_client_id"),
            client_secret=self.config.get_conf("microsoft_entra_client_secret"),
        )
        graph_client = GraphServiceClient(credential, scopes)  # type: ignore

        # Execute
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.create_groups(graph_client))

    # Start the main loop
    def start(self):
        period = self.config.get_conf("collector_period", default=3600, is_number=True)
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASMicrosoftEntra = OpenBASMicrosoftEntra()
    openBASMicrosoftEntra.start()
