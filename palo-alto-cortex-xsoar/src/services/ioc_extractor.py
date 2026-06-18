import json
import os
from concurrent.futures import ProcessPoolExecutor
from typing import List

from msticpy.transform import iocextract
from pydantic import BaseModel, Field

# Add custom IOC types
IOC_EXTRACTOR = iocextract.IoCExtract()
IOC_EXTRACTOR.add_ioc_type(
    ioc_type="uuid",
    ioc_regex=r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
)
IOC_EXTRACTOR.add_ioc_type(
    ioc_type="timestamp",
    ioc_regex=r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b",
)
IOC_EXTRACTOR.add_ioc_type(
    ioc_type="openaev_implant",
    ioc_regex=r"oaev-implant-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}-agent-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
)
IOC_EXTRACTOR.add_ioc_type(
    ioc_type="action", ioc_regex=r"(?:Detected|Prevented)\s\(Reported\)"
)


class IndicatorResults(BaseModel):
    """
    Pydantic model for the categorized indicators.
    """

    ipv4: List[str] = Field(default_factory=list)
    ipv6: List[str] = Field(default_factory=list)
    uuid: List[str] = Field(default_factory=list)
    timestamp: List[str] = Field(default_factory=list)
    hostname: List[str] = Field(default_factory=list)
    file_hashes: List[str] = Field(default_factory=list)
    command_line: List[str] = Field(default_factory=list)
    url: List[str] = Field(default_factory=list)
    oaev_implant: List[str] = Field(default_factory=list)


class IncidentResult(BaseModel):
    """
    Pydantic model for the top-level incident entry.
    """

    id: str
    action: List[str] = Field(default_factory=list)
    indicators: IndicatorResults


def extract_indicators(item):
    """
    Extracts various Indicators of Compromise (IOCs) from a single incident item.

    This function targets the 'CustomFields' dictionary within the item,
    stringifies it, and uses MSTICPy's IoCExtract to find common indicators.
    It also handles custom-defined IOC types for UUIDs, timestamps, and
    OpenAEV implants.

    Args:
        item (dict): A dictionary representing an XSOAR incident,
                     containing at least a 'CustomFields' key.

    Returns:
        dict: A dictionary of raw extracted indicators categorized by type.
    """
    iocs = {}

    # Target CustomFields and stringify it for bulk analysis
    custom_fields = item.get("CustomFields", {})
    combined_text = json.dumps(custom_fields)

    # 1. Extract using MSTICPy IoCExtract
    found_iocs = IOC_EXTRACTOR.extract(combined_text, include_paths=True)

    # Map MSTICPy results to the requested keys
    iocs["ipv4"] = list(found_iocs.get("ipv4", set()))
    iocs["ipv6"] = list(found_iocs.get("ipv6", set()))
    iocs["uuid"] = list(found_iocs.get("uuid", set()))
    iocs["timestamp"] = list(found_iocs.get("timestamp", set()))
    iocs["hostname"] = list(found_iocs.get("dns", set()))

    # File hashes
    iocs["file_hashes"] = list(
        found_iocs.get("md5_hash", set())
        | found_iocs.get("sha1_hash", set())
        | found_iocs.get("sha256_hash", set())
    )

    # Command-line fragments (merged windows_path and linux_path)
    iocs["command_line"] = list(
        found_iocs.get("windows_path", set()) | found_iocs.get("linux_path", set())
    )

    # Other indicators
    iocs["url"] = list(found_iocs.get("url", set()))
    iocs["oaev_implant"] = list(found_iocs.get("openaev_implant", set()))
    iocs["action"] = list(found_iocs.get("action", set()))

    return iocs


def process_item(item):
    """
    Helper function to process a single item for parallel execution.
    Returns a dictionary matching the IncidentResult model structure.
    """
    raw_indicators = extract_indicators(item)
    # Extract action from indicators and move it to top level
    action = raw_indicators.pop("action", [])

    # Create the IncidentResult model to validate the data
    incident_result = IncidentResult(
        id=str(item.get("id", "")),
        action=action,
        indicators=IndicatorResults(**raw_indicators),
    )

    return incident_result


def extract_from_custom_fields(items) -> List[IncidentResult]:
    """
    Extracts IOCs from a list of items using parallel processing.

    This is the primary functional interface for the extraction logic.
    It takes a list of incident dictionaries, each expected to have an
    'id' and a 'CustomFields' dictionary.

    Args:
        items (list): A list of dictionaries, where each dictionary represents
                      an incident and contains 'id' and 'CustomFields'.

    Returns:
        List[IncidentResult]: A list of IncidentResult Pydantic models.
    """
    if not items:
        return []

    # Determine the number of workers based on CPU count and item count
    max_workers = min(os.cpu_count() or 1, len(items))
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        all_results = list(executor.map(process_item, items))

    return all_results
