"""Parameters of the Elasticsearch cluster targeted by the integration tests."""

from pathlib import Path

from pydantic import FilePath, SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

ENV_FILE = Path(__file__).parent / "integration_test.env"


class IntegrationSettings(BaseSettings):
    """Cluster URL and credentials, read from ``integration_test.env`` only.

    Variables exported in the shell are ignored, so a collector configuration
    lying around in the environment never leaks into the tests. Relative paths
    are resolved from the directory holding ``integration_test.env``.
    """

    model_config = SettingsConfigDict(env_file=ENV_FILE)

    elastic_search_url: str
    ca_cert_path: FilePath
    elastic_user: str
    elastic_password: SecretStr
    elastic_api_key: SecretStr
    elastic_cert_path: FilePath
    elastic_key_path: FilePath

    @field_validator(
        "ca_cert_path", "elastic_cert_path", "elastic_key_path", mode="before"
    )
    @classmethod
    def _resolve_from_env_file(cls, value: str) -> Path:
        """Resolve a relative path from the env file directory."""
        return ENV_FILE.parent / Path(value).expanduser()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Read the env file and leave out the process environment."""
        return init_settings, dotenv_settings
