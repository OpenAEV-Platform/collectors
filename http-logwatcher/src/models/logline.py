from datetime import datetime
from pathlib import Path

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
