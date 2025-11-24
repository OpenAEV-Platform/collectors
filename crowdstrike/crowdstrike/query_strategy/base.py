from abc import ABC, abstractmethod

from pyoaev.exceptions import OpenAEVError
from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import SignatureTypes


class Base(ABC):
    def __init__(self, api_handler):
        self.api = api_handler

    @abstractmethod
    def get_raw_data(self, start_time):
        pass

    @abstractmethod
    def extract_signature_data(self, data_item, signature_type: SignatureTypes):
        pass

    @abstractmethod
    def is_prevented(self, data_item) -> bool:
        pass

    @abstractmethod
    def get_alert_id(self, data_item) -> str:
        pass

    def get_signature_data(self, data_item, signature_types: list[SignatureType]):
        data = {}
        for signature_type in signature_types:
            try:
                data[signature_type.label.value] = (
                    signature_type.make_struct_for_matching(
                        self.extract_signature_data(data_item, signature_type.label)
                    )
                )
            except OpenAEVError as oe:
                self.api.logger.warning(f"Skipping signature type: {oe}")
                continue
        return data
