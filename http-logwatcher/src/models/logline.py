from enum import Enum
from pathlib import Path
import re

from pydantic import BaseModel


class SourceEnum(Enum):
    ACCESS = 'access'
    ERROR = 'error'

class LogLine(BaseModel):
    ip_source: str
    source: SourceEnum
    filepath : Path

    class Config:
        use_enum_values = True
