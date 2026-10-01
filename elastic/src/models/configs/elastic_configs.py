"""Configuration for Elastic Security integration."""

import base64
import os
from datetime import timedelta
from pathlib import Path
from typing import Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from src.models.configs import ConfigBaseSettings
from enum import Enum

PKI_CERT_DIR = Path("src/pki")
DEFAULT_CLIENT_CERT_PATH = PKI_CERT_DIR / "pki-client.crt"
DEFAULT_CLIENT_KEY_PATH = PKI_CERT_DIR / "pki-client.key"

class AuthenticationType(str, Enum):
    """Enum for supported authentication types."""
    API_KEY = "API_KEY"
    USER_PASSWORD = "USER_PASSWORD"
    PKI = "PKI"

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
    authentication_type: Optional[AuthenticationType] = Field(
        alias="ELASTIC_AUTHENTICATION_TYPE",
        default=None,
        description=(
            "Authentication method to use for Elasticsearch. One of: "
            "API_KEY, USER_PASSWORD, PKI. If unset, the collector infers the "
            "method from the other settings (API key takes precedence over "
            "username/password, which takes precedence over PKI)."
        ),
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
        default=3,
        description="Maximum number of retry attempts. Combined with offset, this "
        "bounds how long the collector waits for a *matching* alert to appear "
        "after an inject (default 3 x 30s ~= 1.5 min of detection latency: SIEM "
        "ingestion + detection-rule schedule). It is applied per expectation, so "
        "with the blocking batch a large value slows the whole run; raise it via "
        "the catalog only for deployments with genuinely high detection latency. "
        "Too small a value risks a premature 'Not Detected'.",
    )
    offset: timedelta = Field(
        alias="ELASTIC_OFFSET",
        default=timedelta(seconds=30),
        description="Time waited between retry attempts, also used to widen the "
        "search window on each retry.",
    )
    verify_ssl: bool = Field(
        alias="ELASTIC_VERIFY_SSL",
        default=True,
        description="Whether to verify the Elasticsearch TLS certificate. Keep "
        "true in production; disabling it exposes credentials to interception.",
    )
    ca_cert: str | None = Field(
        alias="ELASTIC_CA_CERT",
        default=None,
        description="Optional path to a CA certificate bundle used to verify the "
        "Elasticsearch TLS certificate (recommended for self-signed clusters "
        "instead of disabling verification). Overrides ELASTIC_VERIFY_SSL.",
    )
    client_cert: Optional[str] = Field (
        alias="ELASTIC_CLIENT_CERT",
        default=None,
        description="Single line base64 encoded PEM client certificate for PKI authentication. ",
    )
    client_key: Optional[SecretStr] = Field(
        alias="ELASTIC_CLIENT_KEY",
        default=None,
        description="Single line base64 encoded PEM client key for PKI authentication.",
    )

    @field_validator("events_index", "query_template", "ca_cert", mode="before")
    @classmethod
    def _empty_str_to_none(cls, value: object) -> object:
        """Treat an explicitly empty/whitespace value as unset (None).

        These fields carry a non-None default (or are used as an optional path),
        so an explicitly empty value must mean "unset" rather than "" :
        ``ELASTIC_EVENTS_INDEX=`` disables the drilldown (``drilldown_enabled`` is
        ``bool(events_index)``), ``ELASTIC_QUERY_TEMPLATE=`` falls back to the
        built-in query, and ``ELASTIC_CA_CERT=`` leaves TLS on ``verify_ssl``.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def _validate_auth(self) -> "_ConfigLoaderElastic":
        """Ensure an API key, a username/password pair or a client certificate and key is configured.

        Returns:
            The validated configuration instance.

        Raises:
            ValueError: If no usable authentication method is configured.

        """
        if (
            not self.api_key
            and not (self.username and self.password)
            and not (self.client_cert and self.client_key)
        ):
            raise ValueError(
                "Elastic authentication requires ELASTIC_API_KEY, both "
                "ELASTIC_USERNAME and ELASTIC_PASSWORD, or both "
                "ELASTIC_CLIENT_CERT and ELASTIC_CLIENT_KEY"
            )
        return self

    @field_validator("client_cert", mode="after")
    def _record_client_cert_on_disk(cls, value: Optional[str], info) -> Optional[str]:
        """Write the base64-encoded client certificate to the pki/pki-client.crt file.

        This is needed because requests (and the underlying ssl module) only
        accept a file path for the client certificate and key, not their
        contents. The file is created with mode 0o600 (readable only by the
        current user).

        Args:
            value: The base64-encoded PEM content of the client cert or key.
            info: Validation info, used to determine which field is being
                validated.
        """
        if value is None:
            return None

        pem_content = _decode_base64_pem(value, "ELASTIC_CLIENT_CERT")
        _validate_pem_format(pem_content, "CERTIFICATE")

        pki_dir = PKI_CERT_DIR
        pki_dir.mkdir(parents=True, exist_ok=True)

        cert_path = DEFAULT_CLIENT_CERT_PATH
        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(pem_content if pem_content.endswith("\n") else f"{pem_content}\n")
        os.chmod(cert_path, 0o600)

        return value

    @field_validator("client_key", mode="after")
    def _record_client_key_on_disk(cls, value: Optional[SecretStr], info) -> Optional[str]:
        """Write the base64-encoded client key to the pki/pki-client.key file.

        This is needed because requests (and the underlying ssl module) only
        accept a file path for the client certificate and key, not their
        contents. The file is created with mode 0o600 (readable only by the
        current user).

        Args:
            value: The base64-encoded PEM content of the client cert or key.
            info: Validation info, used to determine which field is being
                validated.
        """
        if value is None:
            return None

        pem_content = _decode_base64_pem(value.get_secret_value(), "ELASTIC_CLIENT_KEY")
        _validate_pem_format(pem_content, "PRIVATE KEY")

        pki_dir = PKI_CERT_DIR
        pki_dir.mkdir(parents=True, exist_ok=True)

        key_path = DEFAULT_CLIENT_KEY_PATH
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(pem_content if pem_content.endswith("\n") else f"{pem_content}\n")
        os.chmod(key_path, 0o600)

        return value


def _decode_base64_pem(value: str, field_name: str) -> str:
    """Decode a base64-encoded PEM string.

    Args:
        value: Base64-encoded PEM content (single-line or wrapped).
        field_name: Name of the field being validated (for error messages).

    Returns:
        The decoded PEM content as a string.

    Raises:
        ValueError: If the base64 decoding fails.

    """
    value_stripped = value.replace("\n", "").replace(" ", "")

    try:
        decoded = base64.b64decode(value_stripped, validate=True)
        return decoded.decode("utf-8")
    except Exception as e:
        raise ValueError(f"{field_name} must be the base64-encoded PEM") from e


def _validate_pem_format(content: str, expected_type: str) -> None:
    """Validate that content is a valid PEM file of the expected type.

    Args:
        content: The PEM content to validate.
        expected_type: Expected PEM type (e.g., "CERTIFICATE", "PRIVATE KEY").

    Raises:
        ValueError: If the PEM format is invalid or type doesn't match.

    """
    content = content.strip()

    if not content.startswith("-----BEGIN "):
        raise ValueError("the decoded value is not PEM")

    if not content.endswith("-----"):
        raise ValueError("the decoded value is not PEM")

    first_line = content.split("\n")[0]
    if expected_type not in first_line:
        raise ValueError("the decoded value is not PEM")

    if expected_type == "PRIVATE KEY" and "ENCRYPTED" in first_line:
        raise ValueError("ELASTIC_CLIENT_KEY must be unencrypted")
