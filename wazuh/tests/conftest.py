"""Pytest configuration and shared fixtures for Wazuh Collector tests."""

import pytest
from datetime import datetime
from typing import Dict, List


@pytest.fixture
def sample_wazuh_alert() -> Dict:
    """Provide a sample Wazuh alert for testing."""
    return {
        '_id': 'test-alert-id-123',
        '_index': 'wazuh-alerts-4.x-2025.11.27',
        'timestamp': '2025-11-27T10:00:00.000Z',
        'rule': {
            'id': '92002',
            'level': 10,
            'description': 'Suspicious PowerShell execution detected',
            'groups': ['sysmon', 'attack'],
            'mitre': {
                'id': ['T1059', 'T1059.001'],
                'technique': ['Command and Scripting Interpreter', 'PowerShell']
            }
        },
        'agent': {
            'id': '001',
            'name': 'WIN-TESTSERVER',
            'ip': '192.168.1.100'
        },
        'data': {
            'win': {
                'eventdata': {
                    'image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                    'parentImage': 'C:\\Temp\\malware.exe',
                    'commandLine': 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass',
                    'md5': 'abc123def456',
                    'sha256': 'def789ghi012jkl345'
                }
            }
        },
        'full_log': 'Sysmon - Event ID 1: Process Creation'
    }


@pytest.fixture
def processed_wazuh_alert() -> Dict:
    """Provide a processed Wazuh alert matching the collector's output format."""
    return {
        '_id': 'test-alert-id-123',
        '_index': 'wazuh-alerts-4.x-2025.11.27',
        'timestamp': '2025-11-27T10:00:00.000Z',
        'rule_id': '92002',
        'rule_level': 10,
        'rule_description': 'Suspicious PowerShell execution detected',
        'rule_groups': ['sysmon', 'attack'],
        'rule_mitre_id': ['T1059', 'T1059.001'],
        'rule_mitre_technique': ['Command and Scripting Interpreter', 'PowerShell'],
        'agent_id': '001',
        'agent_name': 'WIN-TESTSERVER',
        'agent_ip': '192.168.1.100',
        'process_name': 'powershell.exe',
        'process_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'parent_process': 'malware.exe',
        'parent_process_path': 'C:\\Temp\\malware.exe',
        'command_line': 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass',
        'hash_md5': 'abc123def456',
        'hash_sha256': 'def789ghi012jkl345',
        'file_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'full_log': 'Sysmon - Event ID 1: Process Creation'
    }


@pytest.fixture
def sample_expectation() -> Dict:
    """Provide a sample expectation for testing."""
    return {
        'inject_expectation_id': 'exp-test-123',
        'inject_id': 'inject-456',
        'inject_expectation_type': 'DETECTION',
        'inject_expectation_asset': 'asset-789',
        'inject_expectation_group': 'group-1',
        'inject_expectation_signatures': [
            {
                'type': 'process_name',
                'value': 'powershell.exe',
                'inject_expectation_signature_description': 'PowerShell process'
            },
            {
                'type': 'parent_process_name',
                'value': 'malware.exe',
                'inject_expectation_signature_description': 'Malware parent process'
            }
        ],
        'inject_expectation_results': {}
    }


@pytest.fixture
def opensearch_alert_response() -> Dict:
    """Provide a sample OpenSearch API response with alerts."""
    return {
        'took': 5,
        'timed_out': False,
        'hits': {
            'total': {'value': 1, 'relation': 'eq'},
            'hits': [
                {
                    '_index': 'wazuh-alerts-4.x-2025.11.27',
                    '_id': 'test-alert-id-123',
                    '_score': 1.0,
                    '_source': {
                        'timestamp': '2025-11-27T10:00:00.000Z',
                        'rule': {
                            'id': '92002',
                            'level': 10,
                            'description': 'Test alert'
                        },
                        'agent': {
                            'id': '001',
                            'name': 'test-agent'
                        }
                    }
                }
            ]
        }
    }


@pytest.fixture
def mock_config() -> Dict:
    """Provide mock configuration for testing."""
    return {
        'openaev_url': 'http://test-openaev.local',
        'openaev_token': 'test-token-123',
        'collector_id': 'test-collector-wazuh',
        'collector_name': 'Wazuh Collector',
        'collector_min_rule_level': 3,
        'collector_verbose': False,
        'collector_lookback_minutes': 120,
        'indexer_host': 'test-indexer.local',
        'indexer_port': 9200,
        'indexer_username': 'admin',
        'indexer_password': 'admin',
        'indexer_use_ssl': True,
        'indexer_verify_certs': False,
        'indexer_index_pattern': 'wazuh-alerts-*',
        'indexer_alert_limit': 10000,
        'dashboard_url': 'https://test-dashboard.local'
    }
