import logging
from unittest.mock import patch

from pyoaev.configuration import Configuration
from pyoaev.helpers import (
    OpenAEVCollectorHelper,
    OpenAEVConfigHelper,
    OpenAEVDetectionHelper,
)
from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import MatchTypes, SignatureTypes

from crowdstrike.crowdstrike_api_handler import CrowdstrikeApiHandler
from crowdstrike.openaev_crowdstrike import OpenAEVCrowdStrike
from crowdstrike.query_strategy.base import Base

DEFAULT_COLLECTOR_CONFIG = {
    "openaev_url": {"data": "http://fake_openaev_base_url"},
    "openaev_token": {"data": "openaev_uuid_token"},
    # Config information
    "collector_id": {"data": "collector_uuid_identifier"},
    "collector_name": {"data": "CrowdStrike Endpoint Security"},
    "collector_period": {"data": 60},
    "collector_log_level": {"data": "info"},
    "collector_platform": {"data": "windows"},
    # CrowdStrike
    "crowdstrike_client_id": {"data": "some_client_id"},
    "crowdstrike_client_secret": {"data": "very_secret_token"},
    "crowdstrike_api_base_url": {"data": "http://fake_crowdstrike_api_base_url"},
    "crowdstrike_ui_base_url": {"data": "http://fake_crowdstrike_ui_base_url"},
}

DEFAULT_SIGNATURE_TYPES = [
    SignatureType(
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
        match_type=MatchTypes.MATCH_TYPE_FUZZY,
        match_score=95,
    ),
]

FAKE_DOCUMENT = {"document_id": "fake_document_id"}

FAKE_SECURITY_PLATFORM = {"asset_id": "fake_asset_id"}


def get_default_logger() -> logging.Logger:
    return logging.getLogger(__name__)


def get_default_configuration(
    config: dict = DEFAULT_COLLECTOR_CONFIG,
) -> Configuration:
    return Configuration(config_hints=config)


def get_default_signature_types(
    signature_types: [SignatureTypes] = DEFAULT_SIGNATURE_TYPES,
) -> list[SignatureType]:
    return signature_types


def get_default_detection_helper(
    logger: logging.Logger = get_default_logger(),
    signature_types: list[SignatureType] = get_default_signature_types(),
):
    return OpenAEVDetectionHelper(
        logger=logger,
        relevant_signatures_types=[
            signature_type.label.value for signature_type in signature_types
        ],
    )


def get_default_api_handler(
    logger: logging.Logger = get_default_logger(),
    configuration: Configuration = get_default_configuration(),
) -> CrowdstrikeApiHandler:
    return CrowdstrikeApiHandler(
        logger=logger,
        client_id=configuration.get("crowdstrike_client_id"),
        client_secret=configuration.get("crowdstrike_client_secret"),
        base_url=configuration.get("crowdstrike_api_base_url"),
    )


@patch("pyoaev.apis.document.DocumentManager.upsert")
@patch("pyoaev.apis.security_platform.SecurityPlatformManager.upsert")
@patch("pyoaev.mixins.CreateMixin.create")
@patch("builtins.open")
def get_default_collector(
    strategy,
    mock_open,
    _mock_mixin_create,
    mock_security_platform_upsert,
    mock_document_upsert,
    configuration: Configuration = get_default_configuration(),
    detection_helper: OpenAEVDetectionHelper = get_default_detection_helper(),
    signature_types: list[SignatureType] = get_default_signature_types(),
):
    mock_document_upsert.return_value = FAKE_DOCUMENT
    mock_security_platform_upsert.return_value = FAKE_SECURITY_PLATFORM
    mock_open.return_value = None
    return OpenAEVCrowdStrike(
        strategy=strategy,
        configuration=configuration,
        detection_helper=detection_helper,
        signature_types=signature_types,
    )


class TestStrategy(Base):
    def __init__(
        self,
        raw_data_callback: callable,
        signature_data_callback: callable,
        is_prevented_callback: callable,
        get_alert_id_callback: callable,
        api_handler=get_default_api_handler(),
    ):
        super().__init__(api_handler)
        self.raw_data_callback = raw_data_callback
        self.signature_data_callback = signature_data_callback
        self.is_prevented_callback = is_prevented_callback
        self.get_alert_id_callback = get_alert_id_callback

    def get_raw_data(self, start_time):
        return self.raw_data_callback()

    def get_signature_data(self, data_item, signature_types: list[SignatureType]):
        return self.signature_data_callback()

    def is_prevented(self, data_item) -> bool:
        return self.is_prevented_callback()

    def get_alert_id(self, data_item) -> str:
        return self.get_alert_id_callback()

    # implement to placate the linter but not useful as we are
    # shadowing the get_signature_data method
    def extract_signature_data(self, data_item, signature_type: SignatureTypes):
        pass
