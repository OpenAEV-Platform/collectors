from datetime import datetime
from enum import Enum
import hashlib
from pathlib import Path
import re

from pydantic import BaseModel


class LogLine(BaseModel):
    datetimestamp: datetime
    filepath : Path
    ip_source: str
    request: str

    class Config:
        use_enum_values = True

class AccessLogLine(LogLine):
    pass

class ErrorLogLine(LogLine):
    pass
