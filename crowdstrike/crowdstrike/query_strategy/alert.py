from datetime import datetime

from pydantic import BaseModel, ValidationError
from pyoaev.exceptions import OpenAEVError
from pyoaev.signatures.types import SignatureTypes

from crowdstrike.pattern_disposition import is_prevented
from crowdstrike.query_strategy.base import Base


class ProcessDetails(BaseModel):
    filename: str


class DeviceDetails(BaseModel):
    hostname: str


class Item(BaseModel):
    id: str
    filename: str
    parent_details: ProcessDetails
    grandparent_details: ProcessDetails
    device: DeviceDetails
    pattern_disposition: int
    display_name: str
    created_timestamp: str
    updated_timestamp: str
    composite_id: str

    def get_process_image_names(self) -> list[str]:
        return [
            self.filename,
            self.parent_details.filename,
            self.grandparent_details.filename,
        ]

    def get_hostname(self) -> str:
        return self.device.hostname

    def is_prevented(self) -> bool:
        return is_prevented(self.pattern_disposition)


class Alert(Base):
    def get_strategy_name(self):
        return self.__class__

    def get_raw_data(self, start_time: datetime) -> list[Item]:
        items = []
        for dataframe in self.api.get_alerts_v2(start_time):
            try:
                items.append(Item(**dataframe))
            except ValidationError as ve:
                self.api.helper.collector_logger.warning(
                    f"Skipping alert entry because of unexpected data layout: {ve}"
                )
                continue
        return items

    def extract_signature_data(
        self, data_item: Item, signature_type_str: SignatureTypes
    ):
        if signature_type_str == SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME:
            return data_item.get_process_image_names()
        else:
            raise OpenAEVError(
                f"Unsupported signature type: {signature_type_str} by strategy {self.get_strategy_name()}"
            )

    def is_prevented(self, data_item: Item) -> bool:
        return data_item.is_prevented()

    def get_alert_id(self, data_item) -> str:
        return data_item.id
