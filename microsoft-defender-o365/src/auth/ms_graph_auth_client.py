from pathlib import Path

from msal import ConfidentialClientApplication
from msal.authority import AuthorityBuilder, AZURE_PUBLIC

from src.auth.exceptions import AuthenticationError
from src.models.settings.source_configs import _ConfigLoaderSource


class MSGraphAuthClient:
    def __init__(self, config: _ConfigLoaderSource) -> None:
        authority = AuthorityBuilder(AZURE_PUBLIC, config.tenant_id)

        if config.use_certificate_auth:
            client_cert_path = Path(config.client_cert_path)
            if not client_cert_path.exists():
                raise AuthenticationError(f"Certificate file does not exist at path: {client_cert_path.as_posix()}")

            self.app = ConfidentialClientApplication(
                config.client_id,
                authority=authority,
                client_credential={
                    "private_key": client_cert_path.read_text(),
                    "thumbprint": config.client_cert_thumbprint,
                }
            )
        else:
            self.app = ConfidentialClientApplication(
                config.client_id,
                authority=authority,
                client_credential=config.client_secret,
            )

    def get_access_token(self) -> str:
        """Returns a valid bearer token string."""
        result = self.app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )

        if access_token := result.get("access_token"):
            return access_token

        raise AuthenticationError(result.get("error"))
