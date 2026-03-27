from enum import Enum
import re

from pydantic import BaseModel


class SourceEnum(Enum):
    ACCESS = 'access'
    ERROR = 'error'

class LogLine(BaseModel):
    ip_source: str
    source: SourceEnum

    class Config:
        use_enum_values = True
