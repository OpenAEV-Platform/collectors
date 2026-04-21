from typing import Protocol


class SourceDataProtocol(Protocol):
    def to_oaev_data(self):
        ...

    def to_traces_data(self):
        ...
