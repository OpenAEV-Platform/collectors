"""Settings of the GitHub collector, validated at start."""

from datetime import timedelta
from typing import Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pyoaev.configuration import ConfigLoaderCollector

from github_collector.inventory import ALLOWED_PACKAGE_TYPES, DEFAULT_PACKAGE_TYPES


class CollectorConfigOverride(ConfigLoaderCollector):  # type: ignore[misc]
    """The ``collector`` section: base collector fields and the GitHub settings."""

    id: str = Field(
        default="openaev_github",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="GitHub",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="github_collector/img/icon-github.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=6),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )

    # -- API access ----------------------------------------------------------------------
    github_token: SecretStr | None = Field(
        default=None,
        description="Read-only GitHub token (fine-grained: metadata, actions and packages read).",
    )
    github_api_url: str = Field(
        default="https://api.github.com",
        description="GitHub REST API URL; https://<host>/api/v3 for GitHub Enterprise Server.",
    )

    # -- what to collect -------------------------------------------------------------------
    github_organizations: str | None = Field(
        default=None,
        description="Comma-separated organization logins whose repositories are collected.",
    )
    github_users: str | None = Field(
        default=None,
        description="Comma-separated user logins whose own repositories are collected.",
    )
    github_include_archived: bool = Field(
        default=True,
        description="Collect archived repositories (flagged archived).",
    )
    github_include_forks: bool = Field(
        default=False,
        description="Collect forked repositories.",
    )
    github_collect_workflows: bool = Field(
        default=True,
        description="Register each GitHub Actions workflow as a CI/CD pipeline asset.",
    )
    github_collect_packages: bool = Field(
        default=True,
        description="Register GitHub Packages as software package assets when the token can "
        "read them.",
    )
    github_package_types: str = Field(
        default=",".join(DEFAULT_PACKAGE_TYPES),
        description="Comma-separated GitHub Packages types to read (npm, maven, rubygems, "
        "docker, nuget, container).",
    )
    github_end_date_removed: bool = Field(
        default=True,
        description="End-date (never delete) the assets of a repository, workflow or package "
        "no longer returned by GitHub.",
    )

    @field_validator("github_api_url")
    @classmethod
    def _validate_api_url(cls, value: str) -> str:
        """Require an http(s) URL."""
        if not value.startswith(("https://", "http://")):
            raise ValueError(f"github_api_url '{value}' must be an http(s) URL")
        return value.rstrip("/")

    @field_validator("github_package_types")
    @classmethod
    def _validate_package_types(cls, value: str) -> str:
        """Refuse a package type GitHub does not know."""
        unknown = {
            item.strip() for item in value.split(",") if item.strip()
        } - ALLOWED_PACKAGE_TYPES
        if unknown:
            raise ValueError(
                f"unknown GitHub package type(s) {sorted(unknown)}: allowed "
                f"{sorted(ALLOWED_PACKAGE_TYPES)}"
            )
        return value

    @model_validator(mode="after")
    def _validate_scope(self) -> Self:
        """Require a token and at least one owner."""
        if self.github_token is None or not self.github_token.get_secret_value():
            raise ValueError("github_token is required")
        if not (self.github_organizations or self.github_users):
            raise ValueError(
                "set github_organizations or github_users (at least one owner to collect)"
            )
        return self
