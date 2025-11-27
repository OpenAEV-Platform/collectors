"""Data models for Wazuh collector."""

from wazuh_collector.models.config import (
    CollectorConfig,
    DashboardConfig,
    IndexerConfig,
    OpenAEVConfig,
)

__all__ = [
    'OpenAEVConfig',
    'CollectorConfig',
    'IndexerConfig',
    'DashboardConfig',
]
