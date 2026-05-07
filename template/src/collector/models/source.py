from pydantic import BaseModel
from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper
from pyoaev.signatures.types import SignatureTypes
from src.collector.models.data import OAEVData, TraceData
from src.collector.protocols.data_fetcher import DataFetcherProtocol
from src.collector.protocols.source_data import SourceDataProtocol
from src.collector.protocols.source_handler import SourceHandlerProtocol
from src.collector.types.collector import SignatureGroups


class Source(BaseModel):
    """
    A source is defined by three elements:
    - the data fetcher model used to fetch the relevant data from the implemented tool/service
    - the source data model used to serialize and deserialize the fetched data
    - the list of signature types expected to eventually match the data
    """

    data_fetcher_model: type[DataFetcherProtocol]  # or is it type[DataFetcherProtocol]?
    source_data_model: type[SourceDataProtocol]  # or is it type[SourceDataProtocol]?
    signatures: list[SignatureTypes]


class SourceHandler(SourceHandlerProtocol):
    """
    the source handler is an interface between the streamlined collector engine
    and the custom source elements, providing the details for each of the
    following functions:
    - how to fetch the source data using the data fetcher (get_source_data)
    - how to serialize the source data into OAEVData (serialize_as_oaevdata)
    - how to group the signatures from the expectations (get_expectation_signature_groups)
    - how to match the grouped expectation signatures and the OAEVData (match_signature_groups_and_oaevdata)
    - how to serialize the source data into TraceData (serialize_as_tracedata)
    - how to match an expectation and the source data to check for detection/prevention
    """

    def get_source_data(
        self, data_fetcher: DataFetcherProtocol
    ) -> list[SourceDataProtocol]:
        """
        get source data using the data fetcher
        """
        data = data_fetcher.fetch_data()
        # TODO: pass end_date? pass signature_extracted from batch? pass batch? pass context?
        return data

    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> OAEVData:
        """
        serialize provided data as oaevdata
        """
        oaev_data = data.to_oaev_data()
        return oaev_data

    def get_expectation_signature_groups(
        self,
        signatures: list[SignatureTypes],
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> SignatureGroups:
        """
        group the expectation's signatures according to the source provided signatures
        """
        supported_types = {sig_type.value for sig_type in signatures}
        signature_groups: SignatureGroups = {}
        for sig in expectation.inject_expectation_signatures:
            # ignore unsupported signatures according to source
            if sig.type.value not in supported_types:
                continue
            # ignore end_date signature type
            if sig.type.value == "end_date":
                continue
            # create or append to a list of dict-serialized signature data
            signature_groups.setdefault(sig.type.value, []).append(
                {"type": sig.type.value, "value": sig.value}
            )
        return signature_groups

    def match_signature_groups_and_oaevdata(
        self,
        signature_groups: SignatureGroups,
        oaev_data: OAEVData,
        oaev_detection_helper: OpenAEVDetectionHelper,
    ) -> bool:
        """
        matching signatures extracted from an expectation and already filtered against source's signatures
        against the fetched data serialized in an OAEVData format (signature types oriented formating)
        """
        if not oaev_data:
            return False

        for sig_type, signature_data in signature_groups.items():
            try:
                filtered_data = {sig_type: getattr(oaev_data, sig_type)}
            except AttributeError:
                return False
            match_result = oaev_detection_helper.match_alert_elements(
                signature_data, filtered_data
            )
            if not match_result:
                return False
        return True

    def serialize_as_tracedata(self, data: SourceDataProtocol) -> TraceData:
        """
        use pydantic-based TraceData model to serialize then return in dictionary format
        """
        trace = data.to_traces_data()
        return trace

    def match_expectation_and_sourcedata(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        data: SourceDataProtocol,
    ) -> tuple[bool, bool]:
        """
        matching expectation with fetched data to determine
        whether an expectation has been satisfied
        """
        # in any case an expectation is satisfied
        matchflag = False

        # in case a prevention expectation is satisfied to skip useless processing
        breakflag = False

        if isinstance(expectation, PreventionExpectation):
            if data.is_prevented():
                matchflag = True
                breakflag = True
        else:
            if data.is_detected():
                matchflag = True
        return matchflag, breakflag
