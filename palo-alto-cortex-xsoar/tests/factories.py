from factory import Factory, Faker, LazyAttribute, List, SubFactory
from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    ExpectationSignature,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes
from src.models.incident import (
    Alert,
    CustomFields,
    Incident,
)


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


class PreventionExpectationFactory(Factory):
    class Meta:
        model = PreventionExpectation

    inject_expectation_id = Faker("uuid4")
    inject_expectation_signatures = List(
        [
            SubFactory(ExpectationSignatureWithEndDateFactory),
            SubFactory(ExpectationSignatureWithParentProcessNameFactory),
        ]
    )


class AlertFactory(Factory):
    def __new__(cls, *args, **kwargs) -> Alert:
        return super().__new__(*args, **kwargs)

    class Meta:
        model = Alert

    alert_id = Faker("uuid4")
    case_id = Faker("random_int", min=1, max=1000)
    action_pretty = "Detected (Reported)"
    actor_process_command_line = Faker("sentence")
    actor_process_image_name = Faker("file_name", extension="exe")
    actor_process_image_path = Faker("file_path")
    _detection_timestamp = Faker("unix_time")
    detection_timestamp = LazyAttribute(
        lambda obj: int(obj._detection_timestamp) * 1000
    )


class CustomFieldsFactory(Factory):
    class Meta:
        model = CustomFields

    xdralerts = List([SubFactory(AlertFactory)])


class IncidentFactory(Factory):
    class Meta:
        model = Incident

    id = Faker("uuid4")
    name = Faker("sentence")
    custom_fields = SubFactory(CustomFieldsFactory)
