"""OpenSearch/Elasticsearch client for Wazuh indexer."""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


class IndexerClient:
    """Client for querying Wazuh indexer (OpenSearch/Elasticsearch)."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = True,
        verify_certs: bool = False,
        ca_certs: Optional[str] = None,
        index_pattern: str = 'wazuh-alerts-*'
    ):
        """
        Initialize indexer client for Wazuh.

        Args:
            host: Indexer host (e.g., localhost or indexer.example.com)
            port: Indexer port (default: 9200)
            username: Indexer username
            password: Indexer password
            use_ssl: Whether to use SSL/TLS
            verify_certs: Whether to verify SSL certificates
            ca_certs: Path to CA certificates file
            index_pattern: Index pattern for Wazuh alerts
        """
        self.host = host
        self.port = port
        self.index_pattern = index_pattern

        # Configure indexer client
        client_config = {
            'hosts': [{'host': host, 'port': port}],
            'http_auth': (username, password),
            'use_ssl': use_ssl,
            'verify_certs': verify_certs,
            'ssl_show_warn': False
        }

        if ca_certs:
            client_config['ca_certs'] = ca_certs

        try:
            self.client = OpenSearch(**client_config)
            # Test connection
            info = self.client.info()
            logger.info(f"Connected to indexer cluster: {info.get('cluster_name', 'unknown')}")
        except Exception as e:
            logger.error(f"Failed to connect to indexer: {e}")
            raise

    def get_alerts(
        self,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        rule_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 10000
    ) -> List[Dict]:
        """
        Fetch alerts from Wazuh indexer indices.

        Args:
            time_from: Start time for alerts query
            time_to: End time for alerts query
            rule_id: Filter by specific rule ID
            agent_id: Filter by specific agent ID
            limit: Maximum number of alerts to retrieve

        Returns:
            List of alert dictionaries
        """
        # Build query
        query = {
            'bool': {
                'must': []
            }
        }

        # Add time range filter
        if time_from or time_to:
            time_range = {}
            if time_from:
                time_range['gte'] = time_from.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            if time_to:
                time_range['lte'] = time_to.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            query['bool']['must'].append({
                'range': {
                    'timestamp': time_range
                }
            })

        # Add rule ID filter
        if rule_id:
            query['bool']['must'].append({
                'term': {
                    'rule.id': rule_id
                }
            })

        # Add agent ID filter
        if agent_id:
            query['bool']['must'].append({
                'term': {
                    'agent.id': agent_id
                }
            })

        # Build search body
        search_body = {
            'query': query,
            'size': limit,
            'sort': [
                {'timestamp': {'order': 'desc'}}
            ]
        }

        try:
            response = self.client.search(
                index=self.index_pattern,
                body=search_body
            )

            # Extract alerts from response, preserving _id and _index for dashboard links
            hits = response.get('hits', {}).get('hits', [])
            alerts = []
            for hit in hits:
                alert = hit['_source']
                # Add metadata for constructing dashboard links
                alert['_id'] = hit.get('_id')
                alert['_index'] = hit.get('_index')
                alerts.append(alert)

            logger.info(f"Retrieved {len(alerts)} alerts from indexer")
            return alerts

        except Exception as e:
            logger.error(f"Failed to query indexer: {e}")
            return []
