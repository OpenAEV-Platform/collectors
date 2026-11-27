from collections import defaultdict
from datetime import datetime
from typing import Any, Literal

from pydantic import AnyHttpUrl, BaseModel, Field, model_validator
from pyoaev.signatures.types import SignatureTypes
from src.collector.models.data import OAEVData, TraceData
from src.source.models.evidences import Evidence, processEvidence

# bound of the walk up a process tree, against a malformed or cyclic evidence list
MAX_PROCESS_CHAIN_DEPTH = 32

ProcessKey = tuple[str | None, int]


class Alert(BaseModel):
    id: str
    title: str
    status: Literal["unknown", "new", "inProgress", "resolved", "unknownFutureValue"]
    service_source: str = Field(
        ...,
        alias="serviceSource",
        description="The service or product that created this alert.",
    )
    alert_web_url: AnyHttpUrl = Field(
        ...,
        alias="alertWebUrl",
        description="URL for the Microsoft 365 Defender portal alert page.",
    )
    last_activity_date_time: datetime = Field(
        ...,
        alias="lastActivityDateTime",
        description="The oldest activity associated with the alert.",
    )
    last_update_date_time: datetime = Field(
        ...,
        alias="lastUpdateDateTime",
        description="Time when the alert was last updated at Microsoft 365 Defender.",
    )
    evidence: list[Evidence]
    raw: dict[str, Any] = Field(default_factory=dict)
    # ancestor process names read through the hunting drill-down (collectors#611)
    drilldown_process_names: list[str] = Field(default_factory=list, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def save_raw_alert_if_missing_or_empty(cls, data: Any) -> Any:
        if isinstance(data, dict) and not data.get("raw"):
            return {**data, "raw": dict(data)}
        return data

    def _extract_evidences(self) -> defaultdict[SignatureTypes, set[str]]:
        """Cycle through all evidence to extract signature-related elements."""
        evidences_data: defaultdict[SignatureTypes, set[str]] = defaultdict(set)

        for el in self.evidence:
            subdata = el.extract_evidences()
            for key, value in subdata.items():
                evidences_data[key].update(value)

        # a child tool (reg.exe, cmd.exe) inherits the names of its ancestors,
        # so its process evidence matches the implant that started the chain
        inherited = self.chained_process_names() | set(self.drilldown_process_names)
        if inherited:
            evidences_data[SignatureTypes.SIG_TYPE_PROCESS_NAME].update(inherited)
            evidences_data[SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME].update(
                inherited
            )

        return evidences_data

    def process_evidences(self) -> list[processEvidence]:
        """The process evidences of the alert."""
        return [el for el in self.evidence if isinstance(el, processEvidence)]

    def chained_process_names(self) -> set[str]:
        """Names of every ancestor reachable from a process evidence of the alert.

        Process evidences are chained by device, process id and parent process id;
        when both creation times are known they must agree, so a reused process id
        is never taken for the parent. Each ancestor brings its image name and the
        name of its own parent image.
        """
        by_key = self._process_index()
        names: set[str] = set()
        for process in self.process_evidences():
            names.update(self._ancestor_names(process, by_key))
        return names

    def _process_index(self) -> dict[ProcessKey, list[processEvidence]]:
        by_key: dict[ProcessKey, list[processEvidence]] = defaultdict(list)
        for process in self.process_evidences():
            if process.process_id is not None:
                by_key[(process.mde_device_id, process.process_id)].append(process)
        return by_key

    def _ancestor_names(
        self,
        process: processEvidence,
        by_key: dict[ProcessKey, list[processEvidence]],
    ) -> set[str]:
        """Image names of the ancestors of one process evidence in the alert."""
        names: set[str] = set()
        current = process
        seen: set[int] = {id(current)}
        for _ in range(MAX_PROCESS_CHAIN_DEPTH):
            parent = self._find_parent(current, by_key)
            if parent is None or id(parent) in seen:
                break
            seen.add(id(parent))
            names.update(self._image_names(parent))
            current = parent
        return names

    @staticmethod
    def _image_names(process: processEvidence) -> set[str]:
        names = set()
        if process.image_file and process.image_file.file_name:
            names.add(process.image_file.file_name)
        if (
            process.parent_process_image_file
            and process.parent_process_image_file.file_name
        ):
            names.add(process.parent_process_image_file.file_name)
        return names

    @staticmethod
    def _find_parent(
        process: processEvidence,
        by_key: dict[ProcessKey, list[processEvidence]],
    ) -> processEvidence | None:
        if process.parent_process_id is None:
            return None
        candidates = by_key.get((process.mde_device_id, process.parent_process_id), [])
        if process.parent_process_creation_date_time is not None:
            candidates = [
                candidate
                for candidate in candidates
                if candidate.process_creation_date_time is None
                or candidate.process_creation_date_time
                == process.parent_process_creation_date_time
            ]
        # an ambiguous parent (reused process id, no creation time) is not chained
        if len(candidates) != 1:
            return None
        return candidates[0]

    def chain_roots(self) -> list[processEvidence]:
        """Process evidences whose parent is not among the alert's evidences."""
        by_key = self._process_index()
        return [
            process
            for process in self.process_evidences()
            if self._find_parent(process, by_key) is None
        ]

    def prevented_evidences_data(
        self,
    ) -> list[defaultdict[SignatureTypes, set[str]]]:
        """Signature data of each evidence Defender blocked or prevented.

        Each entry holds the elements of ONE prevented evidence, so a prevention
        expectation is validated only by a blocked evidence that itself matches
        the expected process or implant (collectors#675): a blocked process
        carries the names of its ancestors in the alert's process chain, and the
        drill-down ancestors when the alert was drilled down (collectors#611).
        """
        by_key = self._process_index()
        prevented: list[defaultdict[SignatureTypes, set[str]]] = []
        for el in self.evidence:
            if not el.is_prevented():
                continue
            data: defaultdict[SignatureTypes, set[str]] = defaultdict(set)
            for key, value in el.extract_evidences().items():
                data[key].update(value)
            if isinstance(el, processEvidence):
                inherited = self._ancestor_names(el, by_key) | set(
                    self.drilldown_process_names
                )
                if inherited:
                    data[SignatureTypes.SIG_TYPE_PROCESS_NAME].update(inherited)
                    data[SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME].update(inherited)
            if data:
                prevented.append(data)
        return prevented

    def to_oaev_data(self) -> OAEVData:
        """Serialize the evidence data as an OAEVData object."""
        return self._as_oaev_data(self._extract_evidences())

    @staticmethod
    def _as_oaev_data(data: dict[SignatureTypes, set[str]]) -> OAEVData:
        return OAEVData(
            **{sig_type.value: evidences for sig_type, evidences in data.items()}
        )

    def prevented_evidences_oaev_data(self) -> list[OAEVData]:
        """The OAEVData of each prevented evidence, matched one by one."""
        return [self._as_oaev_data(data) for data in self.prevented_evidences_data()]

    def to_traces_data(self) -> TraceData:
        """Serialize metadata from the alert into a TraceData object."""
        return TraceData(
            alert_name=self.title,
            alert_link=self.alert_web_url,
            alert_date=self.last_activity_date_time,
        )

    def is_prevented(self) -> bool:
        """Determine if the threat is/has been prevented as a whole.

        A prevented evidence is not enough here: it must be correlated with the
        expectation first (prevented_evidences_oaev_data, collectors#675).
        """
        return self.status in ["inProgress", "resolved"]

    def is_detected(self) -> bool:
        """By essence, the element is detected if an alert has been created."""
        return True

    def __str__(self) -> str:
        """Str output for logging purposes."""
        return f"{self.service_source} alert id {self.id}: {self.title}"
