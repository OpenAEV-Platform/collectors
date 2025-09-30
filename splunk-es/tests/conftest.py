"""Conftest file for Pytest fixtures."""

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from pytest import fixture

if TYPE_CHECKING:
    from os import _Environ


def mock_env_vars(os_environ: "_Environ[str]", wanted_env: dict[str, str]) -> Any:
    """Fixture to mock environment variables dynamically and clean up after.

    Args:
        os_environ: The os.environ object to patch.
        wanted_env: Dictionary of environment variables to mock.

    Returns:
        Mock object for environment variable patching.

    """
    mock_env = patch.dict(os_environ, wanted_env)
    mock_env.start()

    return mock_env


@fixture(autouse=True)
def mock_openbas_client() -> Any:
    """Fixture to mock OpenBAS calls and clean up after.

    Auto-applies to all tests to prevent actual OpenBAS API calls.
    Mocks urllib3, pyobas client, and collector daemon setup.

    Yields:
        Tuple of mock objects (urllib, pyobas, daemon_setup).

    """
    mock_urllib = patch("urllib3.connectionpool.HTTPConnectionPool.urlopen")
    mock_pyobas = patch("pyobas.client.OpenBAS.http_request")
    mock_daemon_setup = patch("pyobas.daemons.collector_daemon.CollectorDaemon._setup")

    mock_urllib.start()
    mock_pyobas.start()
    mock_daemon_setup.start()

    yield mock_urllib, mock_pyobas, mock_daemon_setup

    mock_urllib.stop()
    mock_pyobas.stop()
    mock_daemon_setup.stop()


@fixture(autouse=True)
def disable_config_yml() -> Any:
    """Fixture to disable config.yml and .env files for tests, forcing environment variable usage only.

    Auto-applies to all tests to ensure consistent configuration loading
    from environment variables instead of config files.

    Yields:
        Patcher object for the settings customization.

    """

    def fake_settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        from pydantic_settings import EnvSettingsSource

        # Return only environment settings source, ignoring files
        return (
            EnvSettingsSource(
                settings_cls,
                env_ignore_empty=True,
            ),
        )

    patcher = patch(
        "src.models.configs.config_loader.ConfigLoader.settings_customise_sources",
        new=classmethod(fake_settings_customise_sources),
    )
    patcher.start()

    yield patcher

    patcher.stop()
