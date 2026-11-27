from pathlib import Path


class CrowdstrikeCredentials:
    """The CrowdStrike API client credentials, given as values or as files.

    Files are read again on every call to ``read``, so a secrets store that
    rewrites them (Vault Agent, a mounted Kubernetes secret, the Secrets Store
    CSI driver...) rotates the credentials without restarting the collector.
    """

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        client_id_file: str | Path | None = None,
        client_secret_file: str | Path | None = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_id_file = client_id_file
        self.client_secret_file = client_secret_file

    def read(self) -> tuple[str, str]:
        """Return the client ID and secret.

        Raises:
            OSError: when a credential file cannot be read.
            ValueError: when a credential is empty.
        """
        return (
            self._value("client ID", self.client_id, self.client_id_file),
            self._value("client secret", self.client_secret, self.client_secret_file),
        )

    @staticmethod
    def _value(label: str, value: str | None, path: str | Path | None) -> str:
        if path is not None:
            value = Path(path).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError(f"The CrowdStrike {label} is empty.")
        return value
