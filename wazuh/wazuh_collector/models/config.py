"""Configuration models with Pydantic validation."""

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class OpenAEVConfig(BaseModel):
    """OpenAEV platform configuration."""

    url: str = Field(..., description="OpenAEV platform URL")
    token: str = Field(..., description="OpenAEV API token")


class CollectorConfig(BaseModel):
    """Collector-specific configuration."""

    id: str = Field(..., description="Unique collector identifier")
    name: str = Field(default="Wazuh Collector", description="Collector display name")
    period: int = Field(default=60, ge=10, le=3600, description="Collection interval in seconds")
    lookback_minutes: int = Field(
        default=120,
        ge=1,
        le=10080,
        description="How far back to look for alerts (minutes)"
    )
    min_rule_level: int = Field(
        default=3,
        ge=0,
        le=15,
        description="Minimum Wazuh rule level to consider"
    )
    verbose: bool = Field(default=False, description="Enable verbose logging")


class IndexerConfig(BaseModel):
    """Wazuh indexer (OpenSearch/Elasticsearch) configuration."""

    host: str = Field(..., description="Indexer hostname")
    port: int = Field(default=9200, ge=1, le=65535, description="Indexer port")
    username: str = Field(default="admin", description="Indexer username")
    password: str = Field(..., description="Indexer password")
    use_ssl: bool = Field(default=True, description="Use SSL/TLS")
    verify_certs: bool = Field(default=False, description="Verify SSL certificates")
    ca_certs: Optional[str] = Field(default=None, description="Path to CA certificates")
    index_pattern: str = Field(
        default="wazuh-alerts-*",
        description="Index pattern for Wazuh alerts"
    )
    alert_limit: int = Field(
        default=10000,
        ge=100,
        le=50000,
        description="Maximum alerts to retrieve per cycle"
    )

    @field_validator('index_pattern')
    @classmethod
    def validate_index_pattern(cls, v: str) -> str:
        """Validate index pattern format."""
        if not v:
            raise ValueError("Index pattern cannot be empty")
        return v


class DashboardConfig(BaseModel):
    """Wazuh dashboard configuration."""

    url: Optional[str] = Field(
        default=None,
        description="Dashboard base URL for alert links"
    )

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate URL format if provided."""
        if v and not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError("Dashboard URL must start with http:// or https://")
        return v
