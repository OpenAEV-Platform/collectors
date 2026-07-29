from msal import ConfidentialClientApplication
from msal.authority import AZURE_PUBLIC, AuthorityBuilder
from src.auth.exceptions import AuthenticationError
from src.models.settings.source_configs import _ConfigLoaderSource


class MSGraphAuthClient:
    def __init__(self, config: _ConfigLoaderSource) -> None:
        authority = AuthorityBuilder(AZURE_PUBLIC, config.tenant_id)

        if config.use_certificate_auth:
            self.app = ConfidentialClientApplication(
                config.client_id,
                authority=authority,
                client_credential={
                    "private_key": config.client_cert_data,
                    "thumbprint": config.client_cert_thumbprint,
                },
            )
        else:
            self.app = ConfidentialClientApplication(
                config.client_id,
                authority=authority,
                client_credential=config.client_secret,
            )

    def get_access_token(self, force_refresh: bool = False) -> str:
        """Returns a valid bearer token string.

        Args:
            force_refresh: If True, bypasses the MSAL token cache and forces
                a fresh token acquisition from the STS.

        Returns:
            A valid bearer token string.

        Raises:
            AuthenticationError: If MSAL returns an error response or a result
                with no access_token.
        """
        result = self.app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"],
            force_refresh=force_refresh,
        )

        if access_token := result.get("access_token"):
            return access_token

        raise AuthenticationError(result.get("error"))
