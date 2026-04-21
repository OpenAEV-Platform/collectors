from typing import Protocol


class SourceHandlerProtocol(Protocol):

    def get_source_data(self):
        ...

    def get_oaev_data(self):
        ...

    def get_signatures(self):
        ...

    def match_signatures(self):
        ...

    def get_traces_data(self):
        ...

    def match_expectations(self):
        ...
