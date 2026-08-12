from typing import Annotated, Literal, Union

from pydantic import BaseModel, Discriminator, Field, Tag
from pydantic.networks import IPvAnyAddress
from pyoaev.signatures.types import SignatureTypes


class imageFile(BaseModel):
    file_name: str | None = Field(None, alias="fileName")


class processEvidence(BaseModel):
    odata_type: Literal["#microsoft.graph.security.processEvidence"] = Field(
        ..., alias="@odata.type"
    )
    image_file: imageFile | None = Field(None, alias="imageFile")
    parent_process_image_file: imageFile | None = Field(
        None, alias="parentProcessImageFile"
    )
    process_command_line: str | None = Field(None, alias="processCommandLine")

    def extract_evidences(self) -> dict[SignatureTypes, list[str]]:
        process_names = []
        command_lines = []

        if self.image_file and self.image_file.file_name:
            process_names.append(self.image_file.file_name)
        if self.parent_process_image_file and self.parent_process_image_file.file_name:
            process_names.append(self.parent_process_image_file.file_name)
        if self.process_command_line:
            command_lines.append(self.process_command_line)

        return {
            SignatureTypes.SIG_TYPE_PROCESS_NAME: process_names,
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME: process_names,
            SignatureTypes.SIG_TYPE_COMMAND_LINE: command_lines,
        }


class deviceEvidence(BaseModel):
    odata_type: Literal["#microsoft.graph.security.deviceEvidence"] = Field(
        ..., alias="@odata.type"
    )
    device_dns_name: str | None = Field(None, alias="deviceDnsName")
    host_name: str | None = Field(None, alias="hostName")
    last_ip_address: IPvAnyAddress | None = Field(None, alias="lastIpAddress")
    last_external_ip_address: IPvAnyAddress | None = Field(
        None, alias="lastExternalIpAddress"
    )
    ip_interfaces: list[IPvAnyAddress | None] = Field([], alias="ipInterfaces")

    def extract_evidences(self) -> dict[SignatureTypes, list[str]]:
        hostnames = []
        ip_addresses = []

        if self.device_dns_name:
            hostnames.append(self.device_dns_name)
        if self.host_name:
            hostnames.append(self.host_name)
        if self.last_ip_address:
            ip_addresses.append(str(self.last_ip_address))
        if self.last_external_ip_address:
            ip_addresses.append(str(self.last_external_ip_address))
        if self.ip_interfaces:
            ip_addresses.extend(map(str, self.ip_interfaces))

        return {
            SignatureTypes.SIG_TYPE_HOSTNAME: hostnames,
            SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS: hostnames,
            SignatureTypes.SIG_TYPE_IPV4_ADDRESS: ip_addresses,
            SignatureTypes.SIG_TYPE_IPV6_ADDRESS: ip_addresses,
            SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS: ip_addresses,
            SignatureTypes.SIG_TYPE_TARGET_IPV6_ADDRESS: ip_addresses,
        }


class fileDetails(BaseModel):
    file_name: str | None = Field(None, alias="fileName")
    file_path: str | None = Field(None, alias="filePath")


class fileEvidence(BaseModel):
    odata_type: Literal["#microsoft.graph.security.fileEvidence"] = Field(
        ..., alias="@odata.type"
    )
    file_details: fileDetails | None = Field(None, alias="fileDetails")

    def extract_evidences(self) -> dict[SignatureTypes, list[str]]:
        file_names = []

        if self.file_details and self.file_details.file_name:
            file_names.append(self.file_details.file_name)
        if self.file_details and self.file_details.file_path:
            file_names.append(self.file_details.file_path)

        return {
            SignatureTypes.SIG_TYPE_FILE_NAME: file_names,
        }


class ipEvidence(BaseModel):
    odata_type: Literal["#microsoft.graph.security.ipEvidence"] = Field(
        ..., alias="@odata.type"
    )
    ip_address: IPvAnyAddress | None = Field(None, alias="ipAddress")

    def extract_evidences(self) -> dict[SignatureTypes, list[str]]:
        ip_addresses = []

        if self.ip_address:
            ip_addresses.append(str(self.ip_address))

        return {
            SignatureTypes.SIG_TYPE_IPV4_ADDRESS: ip_addresses,
            SignatureTypes.SIG_TYPE_IPV6_ADDRESS: ip_addresses,
            SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS: ip_addresses,
            SignatureTypes.SIG_TYPE_TARGET_IPV6_ADDRESS: ip_addresses,
        }


class genericEvidence(BaseModel):
    odata_type: str = Field(..., alias="@odata.type")

    def extract_evidences(self) -> dict[SignatureTypes, list[str]]:
        return {}


def discriminate_evidence_type(model: dict) -> str:
    odata_type = model.get("@odata.type", "")
    if not "." in odata_type:
        return "generic"
    if odata_type.split(".")[-1] in [
        "fileEvidence",
        "deviceEvidence",
        "processEvidence",
        "ipEvidence",
    ]:
        return odata_type
    return "generic"


type Evidence = Annotated[
    Union[
        Annotated[fileEvidence, Tag("#microsoft.graph.security.fileEvidence")],
        Annotated[deviceEvidence, Tag("#microsoft.graph.security.deviceEvidence")],
        Annotated[processEvidence, Tag("#microsoft.graph.security.processEvidence")],
        Annotated[ipEvidence, Tag("#microsoft.graph.security.ipEvidence")],
        Annotated[genericEvidence, Tag("generic")],
    ],
    Discriminator(discriminate_evidence_type),
]
