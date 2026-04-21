from typing import Protocol


class DataFetcherProtocol(Protocol):
    def fetch_data(self):
        ...
