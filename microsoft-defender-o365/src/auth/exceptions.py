from src.collector.models.exception import CollectorError


class AuthenticationError(CollectorError):
    """Raised when MSAL returns an error response or a result with no access_token.

    Extends CollectorError from the template's exception hierarchy.
    Defined in the O365 collector (e.g. /src/auth/exceptions.py) - not a template exception.
    """

    pass
