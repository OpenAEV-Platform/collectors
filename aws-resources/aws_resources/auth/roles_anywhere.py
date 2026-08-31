"""IAM Roles Anywhere authentication support.

Implements the AWS Signature Version 4 X.509 signing scheme (``AWS4-X509-*``)
used by the IAM Roles Anywhere ``CreateSession`` API. It exchanges an X.509
client certificate and its private key for short-lived AWS credentials, which
are then used for standard SigV4 signed API calls.

See https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication.html
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

SERVICE = "rolesanywhere"
ALGORITHM_RSA = "AWS4-X509-RSA-SHA256"
ALGORITHM_ECDSA = "AWS4-X509-ECDSA-SHA256"
DEFAULT_TIMEOUT = 30

_ROLES_ANYWHERE_ARN_REGION = re.compile(r"^arn:[^:]*:rolesanywhere:([^:]+):")


class RolesAnywhereError(Exception):
    """Raised when the IAM Roles Anywhere session exchange fails."""


def normalize_pem(value: str | None) -> str | None:
    """Restore real newlines in a PEM blob passed through an env var."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return value.replace("\\n", "\n")


def region_from_arn(arn: str) -> str | None:
    """Extract the AWS region from an IAM Roles Anywhere ARN."""
    match = _ROLES_ANYWHERE_ARN_REGION.match(arn or "")
    return match.group(1) if match else None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RolesAnywhereSigner:
    """Signs and issues IAM Roles Anywhere ``CreateSession`` requests."""

    def __init__(
        self,
        *,
        certificate_pem: str,
        private_key_pem: str,
        trust_anchor_arn: str,
        profile_arn: str,
        role_arn: str,
        region: str | None = None,
        certificate_chain_pem: str | None = None,
        private_key_passphrase: str | None = None,
        session_duration: int = 3600,
        session_name: str | None = None,
        endpoint_url: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.trust_anchor_arn = trust_anchor_arn
        self.profile_arn = profile_arn
        self.role_arn = role_arn
        self.session_duration = session_duration
        self.session_name = session_name
        self.timeout = timeout

        resolved_region = region or region_from_arn(trust_anchor_arn)
        if not resolved_region:
            raise RolesAnywhereError(
                "Unable to determine the IAM Roles Anywhere region: set the region "
                "explicitly or provide a fully qualified trust anchor ARN"
            )
        self.region = resolved_region
        self.endpoint_url = (
            endpoint_url or f"https://rolesanywhere.{self.region}.amazonaws.com"
        )

        self.certificate = self._load_certificate(certificate_pem)
        self.private_key = self._load_private_key(
            private_key_pem, private_key_passphrase
        )
        self.certificate_chain = self._load_chain(certificate_chain_pem)

        if isinstance(self.private_key, rsa.RSAPrivateKey):
            self.algorithm = ALGORITHM_RSA
        elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            self.algorithm = ALGORITHM_ECDSA
        else:
            raise RolesAnywhereError(
                "Unsupported private key type for IAM Roles Anywhere: only RSA and "
                "EC keys are supported"
            )

    @staticmethod
    def _load_certificate(certificate_pem: str) -> x509.Certificate:
        if not certificate_pem:
            raise RolesAnywhereError(
                "An IAM Roles Anywhere client certificate is required"
            )
        try:
            return x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        except Exception as error:
            raise RolesAnywhereError(
                f"Invalid IAM Roles Anywhere client certificate: {error}"
            ) from error

    @staticmethod
    def _load_private_key(private_key_pem: str, passphrase: str | None) -> Any:
        if not private_key_pem:
            raise RolesAnywhereError("An IAM Roles Anywhere private key is required")
        try:
            return serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=passphrase.encode("utf-8") if passphrase else None,
            )
        except Exception as error:
            raise RolesAnywhereError(
                f"Invalid IAM Roles Anywhere private key: {error}"
            ) from error

    @staticmethod
    def _load_chain(certificate_chain_pem: str | None) -> list[x509.Certificate]:
        if not certificate_chain_pem:
            return []
        try:
            return list(
                x509.load_pem_x509_certificates(certificate_chain_pem.encode("utf-8"))
            )
        except Exception as error:
            raise RolesAnywhereError(
                f"Invalid IAM Roles Anywhere certificate chain: {error}"
            ) from error

    def _sign(self, string_to_sign: str) -> str:
        payload = string_to_sign.encode("utf-8")
        if self.algorithm == ALGORITHM_RSA:
            signature = self.private_key.sign(
                payload, padding.PKCS1v15(), hashes.SHA256()
            )
        else:
            signature = self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        return signature.hex()

    def _request_body(self) -> bytes:
        body: dict[str, Any] = {
            "durationSeconds": self.session_duration,
            "profileArn": self.profile_arn,
            "roleArn": self.role_arn,
            "trustAnchorArn": self.trust_anchor_arn,
        }
        if self.session_name:
            body["sessionName"] = self.session_name
        return json.dumps(body).encode("utf-8")

    def build_signed_request(
        self, now: datetime | None = None
    ) -> tuple[str, bytes, dict[str, str]]:
        """Build the signed ``CreateSession`` request.

        Returns:
            A tuple of ``(url, body, headers)`` ready to be sent.
        """
        now = now or datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")

        host = self.endpoint_url.split("://", 1)[-1].split("/", 1)[0]
        body = self._request_body()

        encoded_certificate = b64encode(
            self.certificate.public_bytes(serialization.Encoding.DER)
        ).decode("ascii")

        headers = {
            "Content-Type": "application/json",
            "Host": host,
            "X-Amz-Date": amz_date,
            "X-Amz-X509": encoded_certificate,
        }
        if self.certificate_chain:
            headers["X-Amz-X509-Chain"] = ",".join(
                b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode(
                    "ascii"
                )
                for certificate in self.certificate_chain
            )

        signed_headers = ";".join(sorted(name.lower() for name in headers))
        canonical_headers = "".join(
            f"{name.lower()}:{headers[name].strip()}\n"
            for name in sorted(headers, key=lambda item: item.lower())
        )
        canonical_request = "\n".join(
            [
                "POST",
                "/sessions",
                "",
                canonical_headers,
                signed_headers,
                _sha256_hex(body),
            ]
        )

        credential_scope = f"{datestamp}/{self.region}/{SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            [
                self.algorithm,
                amz_date,
                credential_scope,
                _sha256_hex(canonical_request.encode("utf-8")),
            ]
        )

        # IAM Roles Anywhere uses the certificate serial number (decimal) as the
        # access key identifier of the credential scope.
        credential = f"{self.certificate.serial_number}/{credential_scope}"
        headers["Authorization"] = (
            f"{self.algorithm} Credential={credential}, "
            f"SignedHeaders={signed_headers}, Signature={self._sign(string_to_sign)}"
        )

        return f"{self.endpoint_url}/sessions", body, headers

    def create_session(self) -> dict[str, str]:
        """Exchange the certificate for temporary AWS credentials.

        Returns:
            A botocore-compatible credentials metadata dictionary.
        """
        url, body, headers = self.build_signed_request()
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RolesAnywhereError(
                f"IAM Roles Anywhere CreateSession failed with HTTP {error.code}: {detail}"
            ) from error
        except urllib.error.URLError as error:
            raise RolesAnywhereError(
                f"Unable to reach IAM Roles Anywhere endpoint {url}: {error.reason}"
            ) from error

        credential_set = payload.get("credentialSet") or []
        if not credential_set:
            raise RolesAnywhereError(
                "IAM Roles Anywhere CreateSession returned no credentials"
            )

        credentials = credential_set[0].get("credentials") or {}
        for key in ("accessKeyId", "secretAccessKey", "sessionToken", "expiration"):
            if not credentials.get(key):
                raise RolesAnywhereError(
                    f"IAM Roles Anywhere CreateSession response is missing '{key}'"
                )

        return {
            "access_key": credentials["accessKeyId"],
            "secret_key": credentials["secretAccessKey"],
            "token": credentials["sessionToken"],
            "expiry_time": credentials["expiration"],
        }


def build_boto3_session(signer: RolesAnywhereSigner, boto3_module: Any) -> Any:
    """Build a boto3 Session backed by auto-refreshing Roles Anywhere credentials."""
    from botocore.credentials import RefreshableCredentials
    from botocore.session import get_session

    refresh: Callable[[], dict[str, str]] = signer.create_session

    credentials = RefreshableCredentials.create_from_metadata(
        metadata=refresh(),
        refresh_using=refresh,
        method="iam-roles-anywhere",
    )

    botocore_session = get_session()
    botocore_session._credentials = credentials
    botocore_session.set_config_variable("region", signer.region)

    return boto3_module.Session(botocore_session=botocore_session)
