"""Shared fixtures for the AWS resources collector tests."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

TRUST_ANCHOR_ARN = "arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/00000000-0000-0000-0000-000000000001"
PROFILE_ARN = "arn:aws:rolesanywhere:eu-west-1:123456789012:profile/00000000-0000-0000-0000-000000000002"
ROLE_ARN = "arn:aws:iam::123456789012:role/openaev-collector"


def _build_identity(key, passphrase: bytes | None = None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "openaev-tests")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    return {
        "key": key,
        "certificate": certificate,
        "certificate_pem": certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode(),
        "private_key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        ).decode(),
    }


@pytest.fixture(scope="session")
def rsa_identity():
    return _build_identity(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )


@pytest.fixture(scope="session")
def ec_identity():
    return _build_identity(ec.generate_private_key(ec.SECP256R1()))


@pytest.fixture(scope="session")
def encrypted_rsa_identity():
    return _build_identity(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        passphrase=b"s3cret",
    )
