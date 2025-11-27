"""
OpenAEV Wazuh Collector

This collector integrates Wazuh SIEM with OpenAEV to validate security
expectations against Wazuh alerts and detections.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from pyoaev.helpers import (
    OpenAEVCollectorHelper,
    OpenAEVConfigHelper,
    OpenAEVDetectionHelper,
)
from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import MatchTypes, SignatureTypes

from wazuh_collector.services import IndexerClient
from wazuh_collector.utils import SignatureMatcher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WazuhCollector:
    """Wazuh collector for OpenAEV."""

    def __init__(
        self,
        config: OpenAEVConfigHelper,
        helper: OpenAEVCollectorHelper,
        detection_helper: OpenAEVDetectionHelper,
        indexer_client: IndexerClient,
        strategy: SignatureMatcher
    ):
        """
        Initialize Wazuh collector.

        Args:
            config: OpenAEV configuration helper
            helper: OpenAEV collector helper
            detection_helper: OpenAEV detection helper
            indexer_client: Indexer client instance
            strategy: Wazuh alert strategy for signature extraction
        """
        self.config = config
        self.helper = helper
        self.detection_helper = detection_helper
        self.indexer_client = indexer_client
        self.strategy = strategy
        self.lookback_minutes = 180  # How far back to look for alerts (increased to 3 hours)
        self.min_rule_level = config.get_conf("collector_min_rule_level") or 3  # Minimum rule level for detection
        self.verbose = str(config.get_conf("collector_verbose")).lower() == "true"  # Enable verbose logging
        
    def process_alert(self, alert: Dict) -> Dict:
        """
        Process and normalize a Wazuh alert from the indexer.

        Args:
            alert: Raw Wazuh alert from the indexer

        Returns:
            Processed alert dictionary
        """
        rule = alert.get('rule', {})
        agent = alert.get('agent', {})
        data = alert.get('data', {})

        # Extract process information (Windows Sysmon data)
        win_eventdata = data.get('win', {}).get('eventdata', {})

        # Extract file integrity monitoring data
        syscheck = data.get('syscheck', {})

        process_id = win_eventdata.get('processId', '')
        parent_image = win_eventdata.get('parentImage', '')

        # Extract just the filename from the full path for better matching
        # e.g., "C:\...\oaev-implant-xxx.exe" -> "oaev-implant-xxx.exe"
        parent_process_name = parent_image.split('\\')[-1] if parent_image else ''
        # Remove .exe extension for matching
        if parent_process_name.lower().endswith('.exe'):
            parent_process_name = parent_process_name[:-4]

        # Log alerts with specific process IDs or implant in parentImage
        if process_id == '17104' or 'oaev-implant' in parent_image:
            logger.info(f"Found alert - ProcessID: {process_id}, ParentImage: {parent_image}, ExtractedName: {parent_process_name}")

        processed = {
            'timestamp': alert.get('timestamp'),
            'rule_id': str(rule.get('id', '')),
            'rule_level': rule.get('level'),
            'rule_description': rule.get('description'),
            'rule_groups': rule.get('groups', []),
            'rule_mitre_id': rule.get('mitre', {}).get('id', []) if isinstance(rule.get('mitre'), dict) else [],
            'rule_mitre_technique': rule.get('mitre', {}).get('technique', []) if isinstance(rule.get('mitre'), dict) else [],
            'agent_id': str(agent.get('id', '')),
            'agent_name': agent.get('name', ''),
            'agent_ip': agent.get('ip', ''),
            'full_log': alert.get('full_log', ''),
            'process_id': process_id,

            # Windows Sysmon fields
            'process_name': win_eventdata.get('image', ''),
            'parent_process': parent_process_name,  # Use extracted filename, not full path
            'command_line': win_eventdata.get('commandLine', ''),

            # File Integrity Monitoring fields
            'file_path': syscheck.get('path', ''),
            'hash_md5': syscheck.get('md5_after', ''),
            'hash_sha1': syscheck.get('sha1_after', ''),
            'hash_sha256': syscheck.get('sha256_after', ''),

            # Preserve OpenSearch metadata for dashboard links
            '_id': alert.get('_id'),
            '_index': alert.get('_index'),
        }

        return processed
    
    def match_expectation(
        self,
        expectation: Dict,
        alert: Dict
    ) -> bool:
        """
        Determine if an alert matches an expectation using detection_helper.

        Args:
            expectation: OpenAEV expectation dictionary to match
            alert: Processed Wazuh alert

        Returns:
            True if alert matches expectation
        """
        # Get signature data from alert using the strategy
        alert_data = self.strategy.get_signature_data(alert)

        # Use detection_helper to match alert against expectation signatures
        is_match = self.detection_helper.match_alert_elements(
            signatures=expectation.get('inject_expectation_signatures', []),
            alert_data=alert_data
        )

        if is_match:
            logger.info(
                f"Matched expectation {expectation.get('inject_expectation_id')} "
                f"with alert rule ID: {alert.get('rule_id')}"
            )

        return is_match
    
    def determine_outcome(
        self,
        alert: Dict,
        expectation: Dict
    ) -> bool:
        """
        Determine if the alert represents a successful detection.

        Note: Wazuh collector only supports DETECTION expectations.
        Prevention expectations are not supported as Wazuh is a detection-focused SIEM.

        Args:
            alert: Processed Wazuh alert
            expectation: Matched expectation dictionary

        Returns:
            True if attack was successfully detected
        """
        # Check rule level against minimum threshold
        rule_level = alert.get('rule_level', 0)

        # Wazuh rule levels:
        # 0-2: Informational
        # 3-4: Low priority
        # 5-7: Medium priority
        # 8-11: High priority
        # 12+: Critical

        # Detection: Alert was generated (rule level >= min_rule_level)
        if rule_level >= self.min_rule_level:
            logger.info(
                f"Alert represents DETECTION - "
                f"Rule: {alert.get('rule_id')}, Level: {rule_level} (threshold: {self.min_rule_level})"
            )
            return True
        else:
            logger.info(
                f"Alert below detection threshold - "
                f"Rule: {alert.get('rule_id')}, Level: {rule_level} (threshold: {self.min_rule_level})"
            )
            return False


def run_collector():
    """Main entry point for the Wazuh collector."""
    logger.info("Initializing Wazuh collector...")

    # Initialize configuration helper
    config = OpenAEVConfigHelper(
        __file__,
        {
            # OpenAEV API
            "openaev_url": {
                "env": "OPENAEV_URL",
                "file_path": ["openaev", "url"]
            },
            "openaev_token": {
                "env": "OPENAEV_TOKEN",
                "file_path": ["openaev", "token"]
            },

            # Collector configuration
            "collector_id": {
                "env": "COLLECTOR_ID",
                "file_path": ["collector", "id"]
            },
            "collector_name": {
                "env": "COLLECTOR_NAME",
                "file_path": ["collector", "name"],
                "default": "Wazuh SIEM Collector"
            },
            "collector_type": {
                "env": "COLLECTOR_TYPE",
                "file_path": ["collector", "type"],
                "default": "wazuh",
            },
            "collector_platform": {
                "env": "COLLECTOR_PLATFORM",
                "file_path": ["collector", "platform"],
                "default": "SIEM"
            },
            "collector_period": {
                "env": "COLLECTOR_PERIOD",
                "file_path": ["collector", "period"],
                "is_number": True,
                "default": 60
            },
            "collector_log_level": {
                "env": "COLLECTOR_LOG_LEVEL",
                "file_path": ["collector", "log_level"],
                "default": "info",
            },
            "collector_icon_filepath": {
                "env": "COLLECTOR_ICON_FILEPATH",
                "file_path": ["collector", "icon_filepath"],
                "default": "wazuh_collector/img/icon-wazuh.png",
            },
            "collector_min_rule_level": {
                "env": "COLLECTOR_MIN_RULE_LEVEL",
                "file_path": ["collector", "min_rule_level"],
                "is_number": True,
                "default": 3
            },
            "collector_verbose": {
                "env": "COLLECTOR_VERBOSE",
                "file_path": ["collector", "verbose"],
                "default": "false"
            },

            # Indexer configuration
            "indexer_host": {
                "env": "INDEXER_HOST",
                "file_path": ["indexer", "host"],
                "default": "localhost"
            },
            "indexer_port": {
                "env": "INDEXER_PORT",
                "file_path": ["indexer", "port"],
                "is_number": True,
                "default": 9200
            },
            "indexer_username": {
                "env": "INDEXER_USERNAME",
                "file_path": ["indexer", "username"],
                "default": "admin"
            },
            "indexer_password": {
                "env": "INDEXER_PASSWORD",
                "file_path": ["indexer", "password"]
            },
            "indexer_use_ssl": {
                "env": "INDEXER_USE_SSL",
                "file_path": ["indexer", "use_ssl"],
                "default": True
            },
            "indexer_verify_certs": {
                "env": "INDEXER_VERIFY_CERTS",
                "file_path": ["indexer", "verify_certs"],
                "default": False
            },
            "indexer_ca_certs": {
                "env": "INDEXER_CA_CERTS",
                "file_path": ["indexer", "ca_certs"],
                "default": None
            },
            "indexer_index_pattern": {
                "env": "INDEXER_INDEX_PATTERN",
                "file_path": ["indexer", "index_pattern"],
                "default": "wazuh-alerts-*"
            },
            "indexer_alert_limit": {
                "env": "INDEXER_ALERT_LIMIT",
                "file_path": ["indexer", "alert_limit"],
                "is_number": True,
                "default": 10000
            },

            # Dashboard configuration (for alert links)
            "dashboard_url": {
                "env": "DASHBOARD_URL",
                "file_path": ["dashboard", "url"],
                "default": None
            },
        }
    )

    # Initialize helpers
    helper = OpenAEVCollectorHelper(
        config=config,
        icon="wazuh_collector/img/icon-wazuh.png",
        collector_type="openaev_wazuh",
        security_platform_type=config.get_conf("collector_platform") or "SIEM"
    )

    # Define supported signature types for Wazuh
    # Only use SignatureType objects for types that exist in pyoaev.SignatureTypes
    # Note: pyoaev currently only supports: PARENT_PROCESS_NAME, IP addresses, and dates
    signature_types = [
        SignatureType(
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            match_type=MatchTypes.MATCH_TYPE_FUZZY,
            match_score=85
        ),
    ]

    # Define all supported signature types (including custom ones for Wazuh)
    # These will be registered with the detection helper as strings
    supported_signatures = [
        "parent_process_name",
        "process_name",
        "command_line",
        "file_path",
        "hash_md5",
        "hash_sha256",
        "rule_id",
        "mitre_technique"
    ]

    detection_helper = OpenAEVDetectionHelper(
        helper.collector_logger,
        supported_signatures
    )

    # Initialize indexer client
    indexer_client = IndexerClient(
        host=config.get_conf('indexer_host'),
        port=config.get_conf('indexer_port'),
        username=config.get_conf('indexer_username'),
        password=config.get_conf('indexer_password'),
        use_ssl=config.get_conf('indexer_use_ssl'),
        verify_certs=config.get_conf('indexer_verify_certs'),
        ca_certs=config.get_conf('indexer_ca_certs'),
        index_pattern=config.get_conf('indexer_index_pattern')
    )

    # Initialize alert strategy
    strategy = SignatureMatcher(signature_types, supported_signatures)

    # Initialize collector
    wazuh_collector = WazuhCollector(
        config,
        helper,
        detection_helper,
        indexer_client,
        strategy
    )

    def process_expectations():
        """Process pending expectations."""
        try:
            # Get pending expectations
            helper.collector_logger.info("Gathering expectations for executed injects")
            expectations = helper.api.inject_expectation.expectations_assets_for_source(
                config.get_conf("collector_id")
            )

            if not expectations:
                helper.collector_logger.info("No pending expectations to process")
                return

            helper.collector_logger.info(
                f"Found {len(expectations)} expectations waiting to be matched"
            )

            # Initialize traces list for matched alerts
            traces_to_create = []

            # Verbose logging for expectations
            if wazuh_collector.verbose:
                helper.collector_logger.info("=" * 100)
                helper.collector_logger.info("VERBOSE MODE: Expectation & Signature Details")
                helper.collector_logger.info("=" * 100)
                for idx, expectation in enumerate(expectations, 1):
                    helper.collector_logger.info(f"\n{'='*100}")
                    helper.collector_logger.info(f"Expectation {idx}/{len(expectations)}")
                    helper.collector_logger.info(f"{'='*100}")

                    # Show all expectation fields
                    helper.collector_logger.info("Full Expectation Object:")
                    helper.collector_logger.info(json.dumps(expectation, indent=2, default=str))

                    helper.collector_logger.info(f"\nKey Fields:")
                    helper.collector_logger.info(f"  Expectation ID: {expectation.get('inject_expectation_id')}")
                    helper.collector_logger.info(f"  Inject ID: {expectation.get('inject_id', 'N/A')}")
                    helper.collector_logger.info(f"  Type: {expectation.get('inject_expectation_type', 'N/A')}")
                    helper.collector_logger.info(f"  Asset ID: {expectation.get('inject_expectation_asset', 'N/A')}")
                    helper.collector_logger.info(f"  Group: {expectation.get('inject_expectation_group', 'N/A')}")

                    # Show signatures in detail
                    signatures = expectation.get('inject_expectation_signatures', [])
                    helper.collector_logger.info(f"\n  Signatures to Match ({len(signatures)}):")
                    for sig_idx, sig in enumerate(signatures, 1):
                        helper.collector_logger.info(f"    [{sig_idx}] Type: {sig.get('type', 'N/A')}")
                        helper.collector_logger.info(f"        Value: {sig.get('value', 'N/A')}")
                        helper.collector_logger.info(f"        Description: {sig.get('inject_expectation_signature_description', 'N/A')}")

                helper.collector_logger.info("\n" + "=" * 100)

            # Fetch recent alerts from indexer
            time_from = datetime.now() - timedelta(minutes=wazuh_collector.lookback_minutes)
            alert_limit = config.get_conf("indexer_alert_limit")
            alerts = indexer_client.get_alerts(time_from=time_from, limit=alert_limit)

            if not alerts:
                helper.collector_logger.info("No alerts retrieved from indexer")
                return

            helper.collector_logger.info(f"Retrieved {len(alerts)} alerts from indexer")

            # Process alerts
            processed_alerts = [
                wazuh_collector.process_alert(alert)
                for alert in alerts
            ]

            # Match expectations with alerts
            for exp_idx, expectation in enumerate(expectations, 1):
                expectation_id = expectation.get('inject_expectation_id', 'unknown')

                # Skip PREVENTION expectations - Wazuh only supports DETECTION
                if expectation.get("inject_expectation_type") == "PREVENTION":
                    helper.collector_logger.warning(
                        f"Skipping PREVENTION expectation {expectation_id} - "
                        f"Wazuh collector only supports DETECTION expectations"
                    )
                    continue

                if wazuh_collector.verbose:
                    # Show expectation details
                    exp_type = expectation.get('inject_expectation_type', 'N/A')
                    inject_id = expectation.get('inject_id', 'N/A')
                    asset_id = expectation.get('inject_expectation_asset', 'N/A')
                    signatures = expectation.get('inject_expectation_signatures', [])
                    sig_types = [sig.get('type', 'UNKNOWN') for sig in signatures]

                    helper.collector_logger.info(f"\n{'='*100}")
                    helper.collector_logger.info(f"Matching Expectation {exp_idx}/{len(expectations)}")
                    helper.collector_logger.info(f"  ID: {expectation_id}")
                    helper.collector_logger.info(f"  Type: {exp_type}")
                    helper.collector_logger.info(f"  Inject ID: {inject_id}")
                    helper.collector_logger.info(f"  Asset: {asset_id}")
                    helper.collector_logger.info(f"  Signatures ({len(signatures)}): {', '.join(sig_types)}")
                    helper.collector_logger.info(f"{'='*100}")

                for alert_idx, alert in enumerate(processed_alerts, 1):
                    # Get alert details for logging
                    alert_id = alert.get('rule_id', 'N/A')
                    agent_name = alert.get('agent_name', 'N/A')
                    process = alert.get('process_name', 'N/A') or alert.get('command_line', 'N/A')
                    parent_process = alert.get('parent_process_name', 'N/A')

                    # Truncate long process names
                    if process and len(process) > 60:
                        process = process[:60] + "..."
                    if parent_process and len(parent_process) > 60:
                        parent_process = parent_process[:60] + "..."

                    if wazuh_collector.match_expectation(expectation, alert):
                        # Log MATCH
                        if wazuh_collector.verbose:
                            helper.collector_logger.info(
                                f"  [MATCH] Alert [{alert_idx}/{len(processed_alerts)}] Rule ID: {alert_id} | "
                                f"Agent: {agent_name} | Process: {process} | Parent: {parent_process}"
                            )

                        # Determine outcome
                        success = wazuh_collector.determine_outcome(alert, expectation)

                        # Set result text (only DETECTION is supported)
                        result_text = "Detected" if success else "Not Detected"

                        # Update expectation via API
                        helper.api.inject_expectation.update(
                            expectation["inject_expectation_id"],
                            {
                                "collector_id": config.get_conf("collector_id"),
                                "result": result_text,
                                "is_success": success,
                                "metadata": {
                                    "wazuh_rule_id": alert.get('rule_id'),
                                    "wazuh_rule_description": alert.get('rule_description'),
                                    "wazuh_rule_level": alert.get('rule_level'),
                                    "wazuh_agent_name": alert.get('agent_name'),
                                    "wazuh_timestamp": alert.get('timestamp'),
                                }
                            }
                        )

                        helper.collector_logger.info(
                            f"Updated expectation {expectation.get('inject_expectation_id')} "
                            f"with {'success' if success else 'failure'}"
                        )

                        # Build alert link (if dashboard URL is configured)
                        alert_link = ""
                        dashboard_url = config.get_conf("dashboard_url")
                        if dashboard_url:
                            # Construct direct link to the specific alert in OpenSearch Dashboards
                            alert_id = alert.get('_id')
                            index_pattern = config.get_conf("indexer_index_pattern")

                            if alert_id and index_pattern:
                                # URL encode the alert ID for the query
                                import urllib.parse
                                encoded_alert_id = urllib.parse.quote(f'"{alert_id}"', safe='')

                                # Build link matching OpenSearch Dashboards format
                                alert_link = (
                                    f"{dashboard_url}/app/data-explorer/discover#"
                                    f"?_a=(discover:(columns:!(_source),isDirty:!f,sort:!()),metadata:(indexPattern:'{index_pattern}',view:discover))"
                                    f"&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))"
                                    f"&_q=(filters:!(),query:(language:kuery,query:'_id:{encoded_alert_id}'))"
                                )
                            else:
                                # Fallback to general discover page if no ID available
                                alert_link = f"{dashboard_url}/app/data-explorer/discover"

                        # Build alert name: Level {level} | {description} ({id})
                        rule_level = alert.get('rule_level', 'N/A')
                        rule_description = alert.get('rule_description', 'Wazuh Alert')
                        rule_id = alert.get('rule_id', 'N/A')
                        alert_name = f"Level {rule_level} | {rule_description} ({rule_id})"

                        # Add trace for this matched expectation
                        traces_to_create.append({
                            "inject_expectation_trace_expectation": expectation["inject_expectation_id"],
                            "inject_expectation_trace_source_id": config.get_conf("collector_id"),
                            "inject_expectation_trace_alert_name": alert_name,
                            "inject_expectation_trace_alert_link": alert_link or "",
                            "inject_expectation_trace_date": alert.get('timestamp'),
                        })

                        helper.collector_logger.info(
                            f"Added trace for expectation {expectation.get('inject_expectation_id')}"
                        )

                        # Continue to next alert to capture all matching alerts (like CrowdStrike/Sentinel)
                        # DO NOT break - we want to create traces for all alerts that match this expectation

            # Bulk create all traces for matched expectations
            if traces_to_create:
                helper.collector_logger.info(
                    f"Creating {len(traces_to_create)} expectation traces in OpenAEV"
                )
                helper.api.inject_expectation_trace.bulk_create(
                    payload={"expectation_traces": traces_to_create}
                )
                helper.collector_logger.info("Successfully created expectation traces")

        except Exception as e:
            helper.collector_logger.error(f"Error processing expectations: {e}", exc_info=True)

    # Start the collector loop
    period = config.get_conf("collector_period")
    helper.schedule(process_expectations, period)


if __name__ == "__main__":
    try:
        run_collector()
    except KeyboardInterrupt:
        logger.info("Collector stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        raise
