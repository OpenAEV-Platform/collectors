"""Signature matching utilities for Wazuh alerts."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class SignatureMatcher:
    """Strategy for extracting and matching signature data from Wazuh alerts."""

    def __init__(self, signature_types: List, supported_signatures: List[str]):
        """
        Initialize the signature matcher.

        Args:
            signature_types: List of SignatureType objects for pyoaev-supported types
            supported_signatures: List of all supported signature type strings
        """
        self.signature_types = signature_types
        self.supported_signatures = supported_signatures

    def extract_signature_value(self, alert: Dict, signature_type_str: str) -> Any:
        """
        Extract specific signature data from a Wazuh alert based on string type.

        Args:
            alert: Processed Wazuh alert
            signature_type_str: String name of signature type

        Returns:
            Signature data value(s) - strings are returned as single-item lists for proper matching
        """
        if signature_type_str == 'parent_process_name':
            value = alert.get('parent_process', '')
            return [value] if value else []
        elif signature_type_str == 'process_name':
            value = alert.get('process_name', '')
            return [value] if value else []
        elif signature_type_str == 'command_line':
            value = alert.get('command_line', '')
            return [value] if value else []
        elif signature_type_str == 'file_path':
            value = alert.get('file_path', '')
            return [value] if value else []
        elif signature_type_str == 'hash_md5':
            value = alert.get('hash_md5', '')
            return [value] if value else []
        elif signature_type_str == 'hash_sha256':
            value = alert.get('hash_sha256', '')
            return [value] if value else []
        elif signature_type_str == 'rule_id':
            value = alert.get('rule_id', '')
            return [value] if value else []
        elif signature_type_str == 'mitre_technique':
            # This is already a list
            return alert.get('rule_mitre_technique', [])
        else:
            logger.warning(f"Unsupported signature type: {signature_type_str}")
            return None

    def get_signature_data(self, alert: Dict) -> Dict[str, Any]:
        """
        Extract all configured signature data from an alert.

        Args:
            alert: Processed Wazuh alert

        Returns:
            Dictionary mapping signature types to their formatted data
        """
        data = {}

        # Handle SignatureType objects (with proper matching configuration)
        for signature_type in self.signature_types:
            try:
                signature_name = signature_type.label.value
                extracted_value = self.extract_signature_value(alert, signature_name)
                if extracted_value is not None:
                    data[signature_name] = signature_type.make_struct_for_matching(extracted_value)
            except Exception as e:
                logger.warning(f"Error extracting signature {signature_type.label}: {e}")
                continue

        # Handle string-based custom signatures (simple string matching)
        for signature_name in self.supported_signatures:
            if signature_name not in data:  # Don't override SignatureType data
                try:
                    extracted_value = self.extract_signature_value(alert, signature_name)
                    if extracted_value is not None:
                        # For string-based signatures, just return the value directly
                        data[signature_name] = extracted_value
                except Exception as e:
                    logger.warning(f"Error extracting signature {signature_name}: {e}")
                    continue

        return data
