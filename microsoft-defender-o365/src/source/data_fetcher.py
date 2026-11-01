"""Data fetcher for Microsoft Defender O365 alerts.

Re-exports DefenderO365DataFetcher to maintain the existing import path
for collector_main.py.
"""

from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

# Alias for backward compatibility with existing import path
MicrosoftDefenderO365DataFetcher = DefenderO365DataFetcher

__all__ = ["MicrosoftDefenderO365DataFetcher", "DefenderO365DataFetcher"]
