"""Tests for the IAM Roles Anywhere SigV4-X509 signing implementation."""

import hashlib
import json
from base64 import b64decode
from unittest.mock import MagicMock, patch

import pytest
from aws_resources.auth.roles_anywhere import (
    ALGORITHM_ECDSA,
    ALGORITHM_RSA,
    RolesAnywhereError,
    RolesAnywhereSigner,
    build_boto3_session,
    normalize_pem,
    region_from_arn,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from tests.conftest import PROFILE_ARN, ROLE_ARN, TRUST_ANCHOR_ARN


def make_signer(identity, **overrides):
    kwargs = {
        "certificate_pem": identity["certificate_pem"],
        "private_key_pem": identity["private_key_pem"],
        "trust_anchor_arn": TRUST_ANCHOR_ARN,
        "profile_arn": PROFILE_ARN,
        "role_arn": ROLE_ARN,
    }
    kwargs.update(overrides)
    return RolesAnywhereSigner(**kwargs)


def parse_authorization(headers):
    algorithm, rest = headers["Authorization"].split(" ", 1)
    fields = dict(piece.strip().split("=", 1) for piece in rest.split(", "))
    return algorithm, fields


def recompute_string_to_sign(headers, body, fields, algorithm):
    signed_headers = fields["SignedHeaders"]
    names = signed_headers.split(";")
    canonical_headers = "".join(
        f"{name.lower()}:{headers[name].strip()}\n"
        for name in sorted(
            (h for h in headers if h.lower() in names), key=lambda i: i.lower()
        )
    )
    canonical_request = "\n".join(
        [
            "POST",
            "/sessions",
            "",
            canonical_headers,
            signed_headers,
            hashlib.sha256(body).hexdigest(),
        ]
    )
    scope = fields["Credential"].split("/", 1)[1]
    return "\n".join(
        [
            algorithm,
            headers["X-Amz-Date"],
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )


class TestHelpers:
    def test_normalize_pem_restores_newlines(self):
        assert normalize_pem("a\\nb") == "a\nb"

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_normalize_pem_returns_none_for_blank(self, value):
        assert normalize_pem(value) is None

    def test_region_from_arn(self):
        assert region_from_arn(TRUST_ANCHOR_ARN) == "eu-west-1"

    def test_region_from_arn_returns_none_when_unparseable(self):
        assert region_from_arn("not-an-arn") is None


class TestSignerConstruction:
    def test_region_is_derived_from_trust_anchor_arn(self, rsa_identity):
        signer = make_signer(rsa_identity)
        assert signer.region == "eu-west-1"
        assert signer.endpoint_url == "https://rolesanywhere.eu-west-1.amazonaws.com"

    def test_explicit_region_overrides_arn(self, rsa_identity):
        signer = make_signer(rsa_identity, region="us-east-2")
        assert signer.endpoint_url == "https://rolesanywhere.us-east-2.amazonaws.com"

    def test_missing_region_raises(self, rsa_identity):
        with pytest.raises(
            RolesAnywhereError, match="determine the IAM Roles Anywhere region"
        ):
            make_signer(rsa_identity, trust_anchor_arn="bad-arn")

    def test_rsa_key_selects_rsa_algorithm(self, rsa_identity):
        assert make_signer(rsa_identity).algorithm == ALGORITHM_RSA

    def test_ec_key_selects_ecdsa_algorithm(self, ec_identity):
        assert make_signer(ec_identity).algorithm == ALGORITHM_ECDSA

    def test_encrypted_private_key_requires_passphrase(self, encrypted_rsa_identity):
        with pytest.raises(
            RolesAnywhereError, match="Invalid IAM Roles Anywhere private key"
        ):
            make_signer(encrypted_rsa_identity)

    def test_encrypted_private_key_loads_with_passphrase(self, encrypted_rsa_identity):
        signer = make_signer(encrypted_rsa_identity, private_key_passphrase="s3cret")
        assert signer.algorithm == ALGORITHM_RSA

    def test_invalid_certificate_raises(self, rsa_identity):
        with pytest.raises(
            RolesAnywhereError, match="Invalid IAM Roles Anywhere client certificate"
        ):
            make_signer(rsa_identity, certificate_pem="not a certificate")


class TestSignedRequest:
    def test_request_targets_create_session_endpoint(self, rsa_identity):
        url, _, _ = make_signer(rsa_identity).build_signed_request()
        assert url == "https://rolesanywhere.eu-west-1.amazonaws.com/sessions"

    def test_body_contains_required_arns(self, rsa_identity):
        _, body, _ = make_signer(
            rsa_identity, session_duration=7200, session_name="collector"
        ).build_signed_request()
        payload = json.loads(body)
        assert payload == {
            "durationSeconds": 7200,
            "profileArn": PROFILE_ARN,
            "roleArn": ROLE_ARN,
            "trustAnchorArn": TRUST_ANCHOR_ARN,
            "sessionName": "collector",
        }

    def test_session_name_is_omitted_when_unset(self, rsa_identity):
        _, body, _ = make_signer(rsa_identity).build_signed_request()
        assert "sessionName" not in json.loads(body)

    def test_x509_header_carries_der_certificate(self, rsa_identity):
        _, _, headers = make_signer(rsa_identity).build_signed_request()
        expected = rsa_identity["certificate"].public_bytes(serialization.Encoding.DER)
        assert b64decode(headers["X-Amz-X509"]) == expected

    def test_credential_scope_uses_certificate_serial_number(self, rsa_identity):
        _, _, headers = make_signer(rsa_identity).build_signed_request()
        _, fields = parse_authorization(headers)
        serial = rsa_identity["certificate"].serial_number
        assert fields["Credential"].startswith(f"{serial}/")
        assert fields["Credential"].endswith("/eu-west-1/rolesanywhere/aws4_request")

    def test_chain_header_absent_without_chain(self, rsa_identity):
        _, _, headers = make_signer(rsa_identity).build_signed_request()
        assert "X-Amz-X509-Chain" not in headers

    def test_chain_header_present_with_chain(self, rsa_identity, ec_identity):
        _, _, headers = make_signer(
            rsa_identity, certificate_chain_pem=ec_identity["certificate_pem"]
        ).build_signed_request()
        expected = ec_identity["certificate"].public_bytes(serialization.Encoding.DER)
        assert b64decode(headers["X-Amz-X509-Chain"]) == expected
        _, fields = parse_authorization(headers)
        assert "x-amz-x509-chain" in fields["SignedHeaders"]

    def test_signed_headers_are_sorted_and_cover_all_signed_fields(self, rsa_identity):
        _, _, headers = make_signer(rsa_identity).build_signed_request()
        _, fields = parse_authorization(headers)
        names = fields["SignedHeaders"].split(";")
        assert names == sorted(names)
        assert names == ["content-type", "host", "x-amz-date", "x-amz-x509"]

    def test_rsa_signature_verifies_against_public_key(self, rsa_identity):
        _, body, headers = make_signer(rsa_identity).build_signed_request()
        algorithm, fields = parse_authorization(headers)
        assert algorithm == ALGORITHM_RSA
        string_to_sign = recompute_string_to_sign(headers, body, fields, algorithm)
        rsa_identity["key"].public_key().verify(
            bytes.fromhex(fields["Signature"]),
            string_to_sign.encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def test_ecdsa_signature_verifies_against_public_key(self, ec_identity):
        _, body, headers = make_signer(ec_identity).build_signed_request()
        algorithm, fields = parse_authorization(headers)
        assert algorithm == ALGORITHM_ECDSA
        string_to_sign = recompute_string_to_sign(headers, body, fields, algorithm)
        ec_identity["key"].public_key().verify(
            bytes.fromhex(fields["Signature"]),
            string_to_sign.encode(),
            ec.ECDSA(hashes.SHA256()),
        )


class TestCreateSession:
    def _response(self, payload):
        response = MagicMock()
        response.read.return_value = json.dumps(payload).encode()
        response.__enter__ = lambda self_: self_
        response.__exit__ = lambda *args: False
        return response

    def test_returns_botocore_credentials_metadata(self, rsa_identity):
        payload = {
            "credentialSet": [
                {
                    "credentials": {
                        "accessKeyId": "AKIA_TEST",
                        "secretAccessKey": "secret",
                        "sessionToken": "token",
                        "expiration": "2030-01-01T00:00:00Z",
                    }
                }
            ]
        }
        with patch("urllib.request.urlopen", return_value=self._response(payload)):
            assert make_signer(rsa_identity).create_session() == {
                "access_key": "AKIA_TEST",
                "secret_key": "secret",
                "token": "token",
                "expiry_time": "2030-01-01T00:00:00Z",
            }

    def test_empty_credential_set_raises(self, rsa_identity):
        with patch(
            "urllib.request.urlopen", return_value=self._response({"credentialSet": []})
        ):
            with pytest.raises(RolesAnywhereError, match="returned no credentials"):
                make_signer(rsa_identity).create_session()

    def test_incomplete_credentials_raise(self, rsa_identity):
        payload = {
            "credentialSet": [
                {"credentials": {"accessKeyId": "AKIA_TEST", "secretAccessKey": "s"}}
            ]
        }
        with patch("urllib.request.urlopen", return_value=self._response(payload)):
            with pytest.raises(RolesAnywhereError, match="missing 'sessionToken'"):
                make_signer(rsa_identity).create_session()

    def test_http_error_is_wrapped(self, rsa_identity):
        import urllib.error

        error = urllib.error.HTTPError(
            "https://example.test/sessions", 403, "Forbidden", {}, None
        )
        error.read = lambda: b'{"message":"Invalid or empty profile provided."}'
        with patch("urllib.request.urlopen", side_effect=error):
            with pytest.raises(RolesAnywhereError, match="HTTP 403"):
                make_signer(rsa_identity).create_session()

    def test_network_error_is_wrapped(self, rsa_identity):
        import urllib.error

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            with pytest.raises(RolesAnywhereError, match="Unable to reach"):
                make_signer(rsa_identity).create_session()


class TestBuildBoto3Session:
    def test_session_is_built_with_refreshable_credentials(self, rsa_identity):
        signer = make_signer(rsa_identity)
        signer.create_session = MagicMock(
            return_value={
                "access_key": "AKIA_TEST",
                "secret_key": "secret",
                "token": "token",
                "expiry_time": "2030-01-01T00:00:00Z",
            }
        )
        boto3_module = MagicMock()

        build_boto3_session(signer, boto3_module)

        boto3_module.Session.assert_called_once()
        botocore_session = boto3_module.Session.call_args.kwargs["botocore_session"]
        credentials = botocore_session.get_credentials()
        assert credentials.access_key == "AKIA_TEST"
        assert credentials.token == "token"
        assert botocore_session.get_config_variable("region") == "eu-west-1"
