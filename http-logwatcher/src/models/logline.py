from enum import Enum
from pydantic import BaseModel


class SourceEnum(Enum):
    ACCESS = 'access'
    ERROR = 'error'

class LogLine(BaseModel):
    _raw: str
    source: SourceEnum

    class Config:
        use_enum_values = True
