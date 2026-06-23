import pytest
from unittest.mock import patch
from src.models.incident import Incident, CustomFields
from src.services.ioc_extractor import (
    extract_indicators, 
    process_item, 
    extract_from_custom_fields, 
    IncidentResult,
    ExtractedIOCs,
    IndicatorResults
)

def test_extract_indicators_various_types():
    custom_data = {
        "description": "Found malware on 192.168.1.1 and 2001:db8::1",
        "notes": "UUID: 550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2026-06-22T08:00:00Z",
        "domain": "malicious.com",
        "hashes": "md5: 5d41402abc4b2a76b9719d911017c592",
        "cmd": "C:\\Windows\\System32\\cmd.exe",
        "action_field": "Detected (Reported)"
    }
    incident = Incident(
        id="inc-1",
        CustomFields=CustomFields(xdralerts=[], **custom_data)
    )
    
    result = extract_indicators(incident)
    
    assert isinstance(result, ExtractedIOCs)
    assert "192.168.1.1" in result.indicators.ipv4
    assert "2001:db8::1" in result.indicators.ipv6
    assert "550e8400-e29b-41d4-a716-446655440000" in result.indicators.uuid
    assert "2026-06-22T08:00:00Z" in result.indicators.timestamp
    assert "5d41402abc4b2a76b9719d911017c592" in result.indicators.file_hashes
    # Note: backslashes are double-escaped because of json.dumps in the extractor
    assert "C:\\\\Windows\\\\System32\\\\cmd.exe" in result.indicators.command_line
    assert "Detected (Reported)" in result.action

def test_process_item_success():
    incident = Incident(id="inc-2", CustomFields=CustomFields(xdralerts=[]))
    result = process_item(incident)
    assert isinstance(result, IncidentResult)
    assert result.id == "inc-2"

def test_process_item_failure():
    with patch("src.services.ioc_extractor.extract_indicators") as mock_ext:
        mock_ext.side_effect = Exception("Extraction failed")
        incident = Incident(id="inc-fail", CustomFields=CustomFields(xdralerts=[]))
        result = process_item(incident)
        assert result is None

def test_extract_from_custom_fields():
    incidents = [
        Incident(id="1", CustomFields=CustomFields(xdralerts=[])),
        Incident(id="2", CustomFields=CustomFields(xdralerts=[])),
    ]
    results = extract_from_custom_fields(incidents)
    assert len(results) == 2
    assert results[0].id == "1"
    assert results[1].id == "2"

def test_extract_from_custom_fields_with_failure():
    incidents = [
        Incident(id="1", CustomFields=CustomFields(xdralerts=[])),
        Incident(id="fail", CustomFields=CustomFields(xdralerts=[])),
        Incident(id="2", CustomFields=CustomFields(xdralerts=[])),
    ]

    with patch("src.services.ioc_extractor.ProcessPoolExecutor") as mock_executor:
        # Mock executor to run synchronously so we can use mocks
        mock_instance = mock_executor.return_value.__enter__.return_value
        mock_instance.map.side_effect = lambda f, items: map(f, items)

        with patch("src.services.ioc_extractor.extract_indicators") as mock_ext:
            def side_effect(item):
                if item.id == "fail":
                    raise Exception("Fail")
                return ExtractedIOCs(action=[], indicators=IndicatorResults())
            mock_ext.side_effect = side_effect

            results = extract_from_custom_fields(incidents)
            assert len(results) == 2
            assert results[0].id == "1"
            assert results[1].id == "2"
