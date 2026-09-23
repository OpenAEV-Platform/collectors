"""Configuration for Elastic Security integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr, model_validator
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderElastic(ConfigBaseSettings):
    """Elastic Security API configuration settings.

    Contains connection details, authentication, timing parameters, and retry
    settings for the Elasticsearch integration.
    """

    model_config = {"frozen": False}

    base_url: str = Field(
        alias="ELASTIC_BASE_URL",
        default="https://localhost:9200",
        description="Base URL of the Elasticsearch API (e.g., https://elastic.company.com:9200).",
    )
    api_key: Optional[SecretStr] = Field(
        alias="ELASTIC_API_KEY",
        default=None,
        description="Elasticsearch API key (preferred). When set, it is used instead of username/password.",
    )
    username: Optional[str] = Field(
        alias="ELASTIC_USERNAME",
        default=None,
        description="Username for HTTP basic authentication (used when no API key is set).",
    )
    password: Optional[SecretStr] = Field(
        alias="ELASTIC_PASSWORD",
        default=None,
        description="Password for HTTP basic authentication.",
    )
    alerts_index: Optional[str] = Field(
        alias="ELASTIC_ALERTS_INDEX",
        default=".alerts-security.alerts-*",
        description="Index or index pattern to search for detection alerts.",
    )
    query_template: Optional[str] = Field(
        alias="ELASTIC_QUERY_TEMPLATE",
        default=None,
        description=(
            "Lucene query_string template used to correlate alerts with an "
            "expectation. Supports the placeholders {alerts_index}, "
            "{source_ips}, {target_ips}, {implant_urls}, {implant_names}, "
            "{start_date}, {end_date}, {time_window}. Each list "
            "placeholder is rendered as an OR-joined set of quoted values, so "
            "write e.g. 'host.ip:({source_ips})'. Leave empty to use the "
            "built-in default query. The time range is always applied "
            "separately as an @timestamp filter."
        ),
    )
    events_index: Optional[str] = Field(
        alias="ELASTIC_EVENTS_INDEX",
        default="logs-windows.sysmon_operational-*,logs-endpoint.events.process-*",
        description=(
            "Index pattern of raw endpoint/process events used to drill down "
            "from a detection alert to its source process and recover the "
            "OpenAEV implant marker (from the process / parent-process command "
            "line). This enables deterministic per-inject correlation - two "
            "injects on the same host within the time window are told apart by "
            "their implant/inject id. Leave empty to disable the drilldown and "
            "fall back to host/IP + time correlation only."
        ),
    )
    kibana_url: Optional[str] = Field(
        alias="ELASTIC_KIBANA_URL",
        default=None,
        description=(
            "Kibana base URL used to build trace links. When unset, base_url "
            "is reused with its port rewritten to 5601; set this explicitly "
            "when Kibana is not reachable at that location (e.g. behind a "
            "reverse proxy or with no port in base_url)."
        ),
    )
    time_window: Optional[timedelta] = Field(
        alias="ELASTIC_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates are provided.",
    )
    max_retry: int = Field(
        alias="ELASTIC_MAX_RETRY",
        default=5,
        description="Maximum number of retry attempts for API calls. Combined "
        "with offset, this defines how long the collector keeps looking for an "
        "alert after an inject (default 5 x 120s covers ~10 min of detection "
        "latency: SIEM ingestion + detection-rule schedule). Too small a value "
        "makes the collector give up before Elastic Security has raised the "
        "alert and record a premature 'Not Detected'.",
    )
    offset: timedelta = Field(
        alias="ELASTIC_OFFSET",
        default=timedelta(seconds=120),
        description="Time waited between retry attempts, also used to widen the "
        "search window on each retry.",
    )
    verify_ssl: bool = Field(
        alias="ELASTIC_VERIFY_SSL",
        default=True,
        description="Whether to verify the Elasticsearch TLS certificate.",
    )

    @model_validator(mode="after")
    def _validate_auth(self) -> "_ConfigLoaderElastic":
        """Ensure either an API key or a username/password pair is configured.

        Returns:
            The validated configuration instance.

        Raises:
            ValueError: If no usable authentication method is configured.

        """
        if not self.api_key and not (self.username and self.password):
            raise ValueError(
                "Elastic authentication requires either ELASTIC_API_KEY or both "
                "ELASTIC_USERNAME and ELASTIC_PASSWORD"
            )
        return self
