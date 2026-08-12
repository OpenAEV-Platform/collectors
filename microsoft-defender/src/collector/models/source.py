from pydantic import BaseModel, ConfigDict, computed_field
from pyoaev.apis.inject_expectation.model.expectation import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import (  # type: ignore[import-untyped]  # noqa: F401
    SignatureTypes,
)
from src.collector.models.data import OAEVData, TraceData
from src.collector.protocols.data_fetcher import DataFetcherProtocol, FetchParamsHook
from src.collector.protocols.source_data import SourceDataProtocol
from src.collector.protocols.source_handler import SourceHandlerProtocol
from src.collector.types.collector import (
    AlertData,
    ExpectationsList,
    SignatureGroups,
    SourceConfig,
)


class Source(BaseModel):
    """
    A source is defined by three elements:
    - the data fetcher model used to fetch the relevant data from the implemented tool/service
    - the source data model used to serialize and deserialize the fetched data
    - the list of signature types expected to eventually match the data
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    data_fetcher_model: type[DataFetcherProtocol]  # or is it type[DataFetcherProtocol]?
    source_data_model: type[SourceDataProtocol]  # or is it type[SourceDataProtocol]?
    signatures: list[SignatureType]

    @computed_field
    @property
    def relevant_signatures_types(self) -> list[SignatureTypes]:
        return [signature.label for signature in self.signatures]


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

    def __init__(self, config: SourceConfig) -> None:
        """
        attach the source handler object the source config provided through the base collector
        """
        self.config = config

    @staticmethod
    def build_fetch_params_hook(batch: ExpectationsList) -> FetchParamsHook | None:
        return None

    @staticmethod
    def get_source_data(data_fetcher: DataFetcherProtocol) -> list[SourceDataProtocol]:
        """
        get source data using the data fetcher
        """
        data = data_fetcher.fetch_data()
        return data

    @staticmethod
    def serialize_as_oaevdata(data: SourceDataProtocol) -> OAEVData:
        """
        serialize provided data as oaevdata
        """
        oaev_data = data.to_oaev_data()
        return oaev_data

    @staticmethod
    def get_expectation_signature_groups(
        signatures: list[SignatureType],
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> SignatureGroups:
        """
        group the expectation's signatures according to the source provided signatures
        """
        supported_types = {sig.label for sig in signatures}
        signature_groups: SignatureGroups = {}
        for expectation_sig in expectation.inject_expectation_signatures:
            # ignore unsupported signatures according to source
            if expectation_sig.type not in supported_types:
                continue
            # ignore end_date signature type
            if expectation_sig.type == SignatureTypes.SIG_TYPE_END_DATE:
                continue
            # create or append to a list of dict-serialized signature data
            signature_groups.setdefault(expectation_sig.type.value, []).append(
                {"type": expectation_sig.type.value, "value": expectation_sig.value}
            )
        return signature_groups

    @staticmethod
    def get_alert_data_from_oaev_data(
        signatures: list[SignatureType],
        oaev_data: OAEVData,
    ) -> AlertData:
        """
        Formatting the OAEVData into the expected matching format known as alert data in pyoaev,
        based on the matching instructions provided in the SignatureType objects
        """
        alert_data: AlertData = {}
        if not oaev_data:
            return alert_data

        for signature in signatures:
            sig_value = signature.label.value
            try:
                value = getattr(oaev_data, sig_value)
            except AttributeError:
                pass
            else:
                alert_data[sig_value] = signature.make_struct_for_matching(value)
        return alert_data

    @staticmethod
    def match_signature_groups_and_alert_data(
        signature_groups: SignatureGroups,
        alert_data: AlertData,
        oaev_detection_helper: OpenAEVDetectionHelper,
    ) -> bool:
        """
        matching signatures extracted from an expectation and already filtered against source's signatures
        against the fetched data serialized in an OAEVData format turned into alert data
        (signature types oriented formating turned matching oriented formating)
        """
        if not alert_data:
            return False

        for sig_type, signature_data in signature_groups.items():
            if sig_type not in alert_data:
                # if an expected signature type is not available in the alert data,
                # then no need to use the matcher
                return False
            match_result = oaev_detection_helper.match_alert_elements(
                signatures=signature_data,
                alert_data={sig_type: alert_data[sig_type]},
            )
            if not match_result:
                # since matching must be done on all provided signatures,
                # cf. behavior of the helper in pyoaev,
                # fail-fast as soon as one misses
                return False
        return True

    @staticmethod
    def serialize_as_tracedata(data: SourceDataProtocol) -> TraceData:
        """
        use pydantic-based TraceData model to serialize then return in dictionary format
        """
        trace = data.to_traces_data()
        return trace

    @staticmethod
    def match_expectation_and_sourcedata(
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
