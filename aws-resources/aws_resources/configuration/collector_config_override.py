from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_aws_resources",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="AWS Resources",
        description="Collector display name",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    icon_filepath: str | None = Field(
        default="aws_resources/img/icon-aws-resources.png",
        description="Path to the icon file",
    )
    aws_access_key_id: str = Field(
        alias="AWS_ACCESS_KEY",
        description="AWS Access Key ID",
    )
    aws_secret_access_key: str = Field(
        alias="AWS_SECRET_ACCESS_KEY",
        description="AWS Secret Access Key",
    )
    aws_session_token: str = Field(
        alias="AWS_SESSION_TOKEN",
        description="AWS Session Token (for temporary credentials)",
    )
    aws_assume_role_arn: str = Field(
        alias="AWS_ASSUME_ROLE_ARN",
        description="ARN of IAM role to assume",
    )
    aws_regions: str = Field(
        alias="AWS_REGIONS",
        description="Comma-separated list of AWS regions",
    )
