"""The scenarios collector: it follows a channel of the scenarios repository's releases and
hands each new release, once checked, to the platform. Until the platform's interface for it
is known, it runs dry: it checks the release and says what it would send."""

from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

from scenarios.configuration.config_loader import ConfigLoader
from scenarios.github import GitHubSource
from scenarios.run import Collect, DryRunSink


class OpenAEVScenarios(CollectorDaemon):
    def __init__(self, configuration: Configuration) -> None:
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_scenarios",
        )
        repository = str(configuration.get("scenarios_repository"))
        token = configuration.get("scenarios_github_token")
        source = GitHubSource(
            str(configuration.get("scenarios_github_api_url")),
            repository,
            str(token) if token else None,
        )
        self._collect = Collect(
            source,
            DryRunSink(self.logger),
            repository=repository,
            channel=str(configuration.get("scenarios_channel")),
            logger=self.logger,
        )

    def _process_message(self) -> None:
        self._collect.run()


def main() -> None:
    OpenAEVScenarios(configuration=ConfigLoader().to_daemon_config()).start()
