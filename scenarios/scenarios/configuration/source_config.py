import re
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pyoaev.configuration.settings_loader import BaseConfigModel

_REPOSITORY = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")


class SourceConfig(BaseConfigModel):
    """Where the releases come from: a repository's channel, read through the GitHub API."""

    repository: str = Field(
        default="OpenAEV-Platform/scenarios",
        description="The GitHub repository whose releases are collected, as owner/name.",
    )
    channel: Literal["edge", "stable"] = Field(
        default="edge",
        description="The channel followed: edge gets every release, stable the recommended ones.",
    )
    github_api_url: str = Field(
        default="https://api.github.com",
        description="The GitHub REST API the releases are read from, over HTTPS.",
    )
    github_token: SecretStr | None = Field(
        default=None,
        description="A GitHub token that can read the repository, needed while it is private.",
    )
    dry_run: bool = Field(
        default=True,
        description=(
            "Check each release and say what would be sent, sending nothing. Set to false to "
            "send it to the platform's catalogue, which needs a platform that receives "
            "catalogue releases."
        ),
    )

    @field_validator("repository")
    @classmethod
    def _owner_and_name(cls, value: str) -> str:
        if not _REPOSITORY.fullmatch(value) or value.split("/")[1] in {".", ".."}:
            raise ValueError("give the repository as owner/name")
        return value

    @field_validator("github_api_url")
    @classmethod
    def _https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("the GitHub API is read over HTTPS")
        return value
