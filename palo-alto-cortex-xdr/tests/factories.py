from factory import Factory, Faker, LazyAttribute, List, SubFactory
from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    ExpectationSignature,
)
from pyoaev.signatures.types import SignatureTypes
from src.models.alert import Alert


class ExpectationSignatureWithEndDateFactory(Factory):
    class Meta:
        model = ExpectationSignature

    type = SignatureTypes.SIG_TYPE_END_DATE
    value = Faker("iso8601")


class ExpectationSignatureWithParentProcessNameFactory(Factory):
    class Meta:
        model = ExpectationSignature

    type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME
    _uuid = Faker("uuid4")
    value = LazyAttribute(lambda obj: f"oaev-implant-{obj._uuid}")


class DetectionExpectationFactory(Factory):
    class Meta:
        model = DetectionExpectation

    inject_expectation_id = Faker("uuid4")
    inject_expectation_signatures = List(
        [
            SubFactory(ExpectationSignatureWithEndDateFactory),
            SubFactory(ExpectationSignatureWithParentProcessNameFactory),
        ]
    )


class AlertFactory(Factory):
    class Meta:
        model = Alert

    external_id = Faker("uuid4")
    actor_process_command_line = Faker("sentence")
    severity = Faker("random_element", elements=["low", "medium", "high"])
    matching_status = "UNMATCHABLE"
    case_id = Faker("random_int", min=1, max=1000)
    alert_id = Faker("random_int", min=1, max=10000)
    category = "Malware"
    description = Faker("sentence")
    action = "Reported"
    action_pretty = "Detected (Reported)"
    _detection_timestamp = Faker("unix_time")
    detection_timestamp = LazyAttribute(lambda obj: int(obj._detection_timestamp))
