"""Contract compliance: SourceDataProtocol output contract validation.

Ensures MicrosoftDefenderO365SourceData satisfies the template SourceDataProtocol
and returns correct types from each method.
"""

import pytest
from src.collector.models.data import OAEVData, TraceData
from src.collector.protocols.source_data import SourceDataProtocol
from src.source.source_data import MicrosoftDefenderO365SourceData


class TestSourceDataContractCompliance:
    """Verify MicrosoftDefenderO365SourceData adheres to SourceDataProtocol."""

    def test_source_data_satisfies_protocol(self) -> None:
        """Then MicrosoftDefenderO365SourceData satisfies SourceDataProtocol."""
        data = MicrosoftDefenderO365SourceData()
        assert isinstance(data, SourceDataProtocol)

    def test_to_oaev_data_returns_oaev_data(self) -> None:
        """Then to_oaev_data() returns an OAEVData instance."""
        data = MicrosoftDefenderO365SourceData()
        result = data.to_oaev_data()
        assert isinstance(result, OAEVData)

    def test_to_traces_data_returns_trace_data(self) -> None:
        """Then to_traces_data() returns a TraceData instance."""
        data = MicrosoftDefenderO365SourceData()
        result = data.to_traces_data()
        assert isinstance(result, TraceData)

    def test_is_prevented_returns_bool(self) -> None:
        """Then is_prevented() returns a bool."""
        data = MicrosoftDefenderO365SourceData()
        result = data.is_prevented()
        assert isinstance(result, bool)

    def test_is_detected_returns_bool(self) -> None:
        """Then is_detected() returns a bool."""
        data = MicrosoftDefenderO365SourceData()
        result = data.is_detected()
        assert isinstance(result, bool)

    def test_str_returns_str(self) -> None:
        """Then __str__() returns a str."""
        data = MicrosoftDefenderO365SourceData()
        result = str(data)
        assert isinstance(result, str)
        assert len(result) > 0
