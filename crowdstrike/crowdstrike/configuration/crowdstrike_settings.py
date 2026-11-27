from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic.json_schema import SkipJsonSchema
from pydantic_settings import BaseSettings


class CrowdstrikeSettings(BaseSettings):
    """CrowdStrike API configuration settings."""

    # The config schema feeds the OpenAEV catalog, whose deployments only pass environment
    # variables: it keeps the values required and leaves out the credential files.
    model_config = {
        "frozen": False,
        "json_schema_extra": {"required": ["client_id", "client_secret"]},
    }

    client_id: str | None = Field(
        default=None,
        description="The CrowdStrike API client ID. Required unless client_id_file is set.",
    )
    client_secret: SecretStr | None = Field(
        default=None,
        description="The CrowdStrike API client secret. Required unless client_secret_file is set.",
    )
    client_id_file: SkipJsonSchema[Path | None] = Field(
        default=None,
        description=(
            "Path to a file holding the CrowdStrike API client ID, for example written by a "
            "secrets store. Read again on every run, so the credentials can be rotated "
            "without restarting the collector."
        ),
    )
    client_secret_file: SkipJsonSchema[Path | None] = Field(
        default=None,
        description=(
            "Path to a file holding the CrowdStrike API client secret, for example written by "
            "a secrets store. Read again on every run, so the credentials can be rotated "
            "without restarting the collector."
        ),
    )
    api_base_url: str = Field(
        default="https://api.us-2.crowdstrike.com",
        description="The base URL for the CrowdStrike APIs. ",
    )
    ui_base_url: str = Field(
        default="https://falcon.us-2.crowdstrike.com",
        description="The base URL for the CrowdStrike UI you use to see your alerts.",
    )

    @field_validator(
        "client_id",
        "client_secret",
        "client_id_file",
        "client_secret_file",
        mode="before",
    )
    @classmethod
    def _empty_as_unset(cls, value):
        # docker-compose passes unset variables as empty strings
        return None if value == "" else value

    @model_validator(mode="after")
    def _check_credentials(self) -> "CrowdstrikeSettings":
        for name in ("client_id", "client_secret"):
            given = getattr(self, name) is not None
            from_file = getattr(self, f"{name}_file") is not None
            if given and from_file:
                raise ValueError(f"Set either {name} or {name}_file, not both.")
            if not given and not from_file:
                raise ValueError(f"{name} or {name}_file is required.")
        return self
