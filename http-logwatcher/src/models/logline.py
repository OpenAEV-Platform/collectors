from pydantic import BaseModel


class LogLine(BaseModel):
    _raw: str
