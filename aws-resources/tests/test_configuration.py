"""Tests for the AWS resources collector configuration and session wiring."""

import os
from unittest.mock import MagicMock, patch

import pytest
from aws_resources.auth.roles_anywhere import RolesAnywhereSigner, normalize_pem
from aws_resources.configuration.collector_config_override import (
    AUTH_TYPE_CREDENTIALS,
    AUTH_TYPE_ROLES_ANYWHERE,
    CollectorConfigOverride,
    normalize_auth_type,
)
from pydantic import ValidationError
from tests.conftest import PROFILE_ARN, ROLE_ARN, TRUST_ANCHOR_ARN

BASE = {"id": "openaev_aws_resources", "name": "AWS Resources"}


def roles_anywhere_config(identity, **overrides):
    values = {
        **BASE,
        "aws_auth_type": AUTH_TYPE_ROLES_ANYWHERE,
        "aws_roles_anywhere_trust_anchor_arn": TRUST_ANCHOR_ARN,
        "aws_roles_anywhere_profile_arn": PROFILE_ARN,
        "aws_roles_anywhere_role_arn": ROLE_ARN,
        "aws_roles_anywhere_certificate": identity["certificate_pem"],
        "aws_roles_anywhere_private_key": identity["private_key_pem"],
    }
    values.update(overrides)
    return values


class TestAuthTypeValidation:
    def test_normalize_auth_type_passes_through_non_strings(self):
        """Non-strings are left for pydantic to reject with a type error."""
        assert normalize_auth_type(42) == 42

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_normalize_auth_type_defaults_when_unset(self, value):
        assert normalize_auth_type(value) == AUTH_TYPE_CREDENTIALS

    @pytest.mark.parametrize("value", ["ROLES_ANYWHERE", " Roles_Anywhere "])
    def test_normalize_auth_type_normalizes_case_and_spacing(self, value):
        assert normalize_auth_type(value) == AUTH_TYPE_ROLES_ANYWHERE

    def test_normalize_auth_type_rejects_unknown_modes(self):
        with pytest.raises(ValueError, match="aws_auth_type must be one of"):
            normalize_auth_type("mtls")

    def test_defaults_to_credentials_mode(self):
        config = CollectorConfigOverride(**BASE)
        assert config.aws_auth_type == AUTH_TYPE_CREDENTIALS

    def test_credentials_mode_does_not_require_aws_keys(self):
        config = CollectorConfigOverride(**BASE)
        assert config.aws_access_key_id == ""
        assert config.aws_secret_access_key == ""

    def test_unknown_auth_type_is_rejected(self):
        with pytest.raises(ValidationError, match="aws_auth_type must be one of"):
            CollectorConfigOverride(**BASE, aws_auth_type="mtls")

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_empty_auth_type_falls_back_to_credentials(self, value):
        config = CollectorConfigOverride(**BASE, aws_auth_type=value)
        assert config.aws_auth_type == AUTH_TYPE_CREDENTIALS

    def test_non_string_auth_type_is_rejected_by_the_type_check(self):
        """Non-string values bypass normalization and fail pydantic's str check."""
        with pytest.raises(ValidationError):
            CollectorConfigOverride(**BASE, aws_auth_type=42)

    @pytest.mark.parametrize("value", ["ROLES_ANYWHERE", " Roles_Anywhere "])
    def test_auth_type_is_normalized(self, value, rsa_identity):
        config = CollectorConfigOverride(
            **roles_anywhere_config(rsa_identity, aws_auth_type=value)
        )
        assert config.aws_auth_type == AUTH_TYPE_ROLES_ANYWHERE

    def test_roles_anywhere_mode_accepts_complete_config(self, rsa_identity):
        config = CollectorConfigOverride(**roles_anywhere_config(rsa_identity))
        assert config.aws_auth_type == AUTH_TYPE_ROLES_ANYWHERE
        assert config.aws_roles_anywhere_session_duration == 3600

    @pytest.mark.parametrize(
        "missing",
        [
            "aws_roles_anywhere_trust_anchor_arn",
            "aws_roles_anywhere_profile_arn",
            "aws_roles_anywhere_role_arn",
            "aws_roles_anywhere_certificate",
            "aws_roles_anywhere_private_key",
        ],
    )
    def test_roles_anywhere_mode_requires_each_field(self, missing, rsa_identity):
        values = roles_anywhere_config(rsa_identity, **{missing: ""})
        with pytest.raises(ValidationError, match=missing):
            CollectorConfigOverride(**values)

    def test_roles_anywhere_fields_not_required_in_credentials_mode(self):
        config = CollectorConfigOverride(**BASE, aws_auth_type=AUTH_TYPE_CREDENTIALS)
        assert config.aws_roles_anywhere_trust_anchor_arn == ""

    @pytest.mark.parametrize("duration", [899, 43201])
    def test_session_duration_bounds_are_enforced(self, duration, rsa_identity):
        values = roles_anywhere_config(
            rsa_identity, aws_roles_anywhere_session_duration=duration
        )
        with pytest.raises(ValidationError):
            CollectorConfigOverride(**values)

    @pytest.mark.parametrize("duration", [900, 3600, 43200])
    def test_session_duration_accepts_valid_values(self, duration, rsa_identity):
        values = roles_anywhere_config(
            rsa_identity, aws_roles_anywhere_session_duration=duration
        )
        assert (
            CollectorConfigOverride(**values).aws_roles_anywhere_session_duration
            == duration
        )


class TestCollectorInitialisation:
    """The constructor maps configuration values onto the collector."""

    @staticmethod
    def _build(values):
        from aws_resources import openaev_aws_resources as module

        configuration = MagicMock()
        configuration.get.side_effect = values.get

        def fake_daemon_init(self, configuration, callback, collector_type):
            self._configuration = configuration
            self.logger = MagicMock()

        with patch.object(module.CollectorDaemon, "__init__", fake_daemon_init):
            return module.OpenAEVAWSResources(configuration)

    def test_auth_type_is_normalized_from_configuration(self):
        collector = self._build({"aws_auth_type": " ROLES_ANYWHERE "})
        assert collector.auth_type == AUTH_TYPE_ROLES_ANYWHERE

    def test_auth_type_defaults_to_credentials(self):
        collector = self._build({})
        assert collector.auth_type == AUTH_TYPE_CREDENTIALS

    def test_credentials_are_read_from_configuration(self):
        collector = self._build(
            {
                "aws_access_key_id": "AKIA_TEST",
                "aws_secret_access_key": "secret",
                "aws_session_token": "token",
                "aws_assume_role_arn": ROLE_ARN,
            }
        )
        assert collector.access_key_id == "AKIA_TEST"
        assert collector.secret_access_key == "secret"
        assert collector.session_token == "token"
        assert collector.assume_role_arn == ROLE_ARN
        assert collector.base_session is None
        assert collector.session is None
        assert collector.aws_clients == {}

    def test_regions_are_split_and_stripped(self):
        collector = self._build({"aws_regions": " eu-west-1 , us-east-1 ,, "})
        assert collector.regions_list == ["eu-west-1", "us-east-1"]

    def test_regions_default_to_discovery_when_unset(self):
        assert self._build({"aws_regions": ""}).regions_list is None


def build_collector(configuration):
    """Instantiate the collector without running CollectorDaemon.__init__."""
    from aws_resources.openaev_aws_resources import OpenAEVAWSResources

    collector = object.__new__(OpenAEVAWSResources)
    collector._configuration = configuration
    collector.logger = MagicMock()
    collector.auth_type = normalize_auth_type(configuration.get("aws_auth_type"))
    collector.access_key_id = configuration.get("aws_access_key_id")
    collector.secret_access_key = configuration.get("aws_secret_access_key")
    collector.session_token = configuration.get("aws_session_token")
    collector.assume_role_arn = configuration.get("aws_assume_role_arn")
    collector.regions_list = ["eu-west-1"]
    collector.base_session = None
    collector.session = None
    return collector


class TestSessionInitialisation:
    def test_static_credentials_path_is_preserved(self):
        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_CREDENTIALS,
                "aws_access_key_id": "AKIA_TEST",
                "aws_secret_access_key": "secret",
                "aws_session_token": "token",
                "aws_assume_role_arn": "",
            }
        )
        with patch("aws_resources.openaev_aws_resources.boto3") as boto3_module:
            collector._init_aws_session()

        boto3_module.Session.assert_called_once_with(
            aws_access_key_id="AKIA_TEST",
            aws_secret_access_key="secret",
            aws_session_token="token",
        )

    def test_default_credential_chain_is_used_without_keys(self):
        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_CREDENTIALS,
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
                "aws_session_token": "",
                "aws_assume_role_arn": "",
            }
        )
        with patch("aws_resources.openaev_aws_resources.boto3") as boto3_module:
            collector._init_aws_session()

        boto3_module.Session.assert_called_once_with()

    def test_regions_are_discovered_when_not_configured(self):
        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_CREDENTIALS,
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
                "aws_session_token": "",
                "aws_assume_role_arn": "",
            }
        )
        collector.regions_list = []
        collector._discover_regions = MagicMock()

        with patch("aws_resources.openaev_aws_resources.boto3"):
            collector._init_aws_session()

        collector._discover_regions.assert_called_once_with()

    def test_configured_regions_skip_discovery(self):
        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_CREDENTIALS,
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
                "aws_session_token": "",
                "aws_assume_role_arn": "",
            }
        )
        collector._discover_regions = MagicMock()

        with patch("aws_resources.openaev_aws_resources.boto3"):
            collector._init_aws_session()

        collector._discover_regions.assert_not_called()

    def test_roles_anywhere_path_builds_certificate_backed_session(self, rsa_identity):
        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_ROLES_ANYWHERE,
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
                "aws_session_token": "",
                "aws_assume_role_arn": "",
                "aws_roles_anywhere_trust_anchor_arn": TRUST_ANCHOR_ARN,
                "aws_roles_anywhere_profile_arn": PROFILE_ARN,
                "aws_roles_anywhere_role_arn": ROLE_ARN,
                "aws_roles_anywhere_certificate": rsa_identity["certificate_pem"],
                "aws_roles_anywhere_private_key": rsa_identity["private_key_pem"],
                "aws_roles_anywhere_certificate_chain": "",
                "aws_roles_anywhere_private_key_passphrase": "",
                "aws_roles_anywhere_region": "",
                "aws_roles_anywhere_session_duration": 3600,
            }
        )
        expected_session = MagicMock()
        with patch(
            "aws_resources.openaev_aws_resources.build_boto3_session",
            return_value=expected_session,
        ) as build_session:
            collector._init_aws_session()

        assert collector.base_session is expected_session
        assert collector.session is expected_session
        signer = build_session.call_args.args[0]
        assert signer.region == "eu-west-1"
        assert signer.session_duration == 3600
        assert signer.session_name == "OpenAEVAWSCollector"

    def test_roles_anywhere_accepts_escaped_newline_pem(self, rsa_identity):
        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_ROLES_ANYWHERE,
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
                "aws_session_token": "",
                "aws_assume_role_arn": "",
                "aws_roles_anywhere_trust_anchor_arn": TRUST_ANCHOR_ARN,
                "aws_roles_anywhere_profile_arn": PROFILE_ARN,
                "aws_roles_anywhere_role_arn": ROLE_ARN,
                "aws_roles_anywhere_certificate": rsa_identity[
                    "certificate_pem"
                ].replace("\n", "\\n"),
                "aws_roles_anywhere_private_key": rsa_identity[
                    "private_key_pem"
                ].replace("\n", "\\n"),
                "aws_roles_anywhere_certificate_chain": "",
                "aws_roles_anywhere_private_key_passphrase": "",
                "aws_roles_anywhere_region": "us-east-1",
                "aws_roles_anywhere_session_duration": 900,
            }
        )
        with patch(
            "aws_resources.openaev_aws_resources.build_boto3_session",
            return_value=MagicMock(),
        ) as build_session:
            collector._init_aws_session()

        signer = build_session.call_args.args[0]
        assert signer.region == "us-east-1"
        assert signer.certificate.serial_number == (
            rsa_identity["certificate"].serial_number
        )

    def test_roles_anywhere_session_is_used_for_assume_role(self, rsa_identity):
        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_ROLES_ANYWHERE,
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
                "aws_session_token": "",
                "aws_assume_role_arn": "arn:aws:iam::123456789012:role/chained",
                "aws_roles_anywhere_trust_anchor_arn": TRUST_ANCHOR_ARN,
                "aws_roles_anywhere_profile_arn": PROFILE_ARN,
                "aws_roles_anywhere_role_arn": ROLE_ARN,
                "aws_roles_anywhere_certificate": rsa_identity["certificate_pem"],
                "aws_roles_anywhere_private_key": rsa_identity["private_key_pem"],
                "aws_roles_anywhere_certificate_chain": "",
                "aws_roles_anywhere_private_key_passphrase": "",
                "aws_roles_anywhere_region": "",
                "aws_roles_anywhere_session_duration": 3600,
            }
        )
        roles_anywhere_session = MagicMock()
        roles_anywhere_session.client.return_value.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA_CHAINED",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }
        with patch(
            "aws_resources.openaev_aws_resources.build_boto3_session",
            return_value=roles_anywhere_session,
        ), patch("aws_resources.openaev_aws_resources.boto3") as boto3_module:
            collector._init_aws_session()

        roles_anywhere_session.client.assert_called_once_with("sts")
        boto3_module.Session.assert_called_once_with(
            aws_access_key_id="AKIA_CHAINED",
            aws_secret_access_key="secret",
            aws_session_token="token",
        )

    def test_roles_anywhere_failure_is_reported(self, rsa_identity):
        from aws_resources.auth.roles_anywhere import RolesAnywhereError

        collector = build_collector(
            {
                "aws_auth_type": AUTH_TYPE_ROLES_ANYWHERE,
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
                "aws_session_token": "",
                "aws_assume_role_arn": "",
                "aws_roles_anywhere_trust_anchor_arn": TRUST_ANCHOR_ARN,
                "aws_roles_anywhere_profile_arn": PROFILE_ARN,
                "aws_roles_anywhere_role_arn": ROLE_ARN,
                "aws_roles_anywhere_certificate": rsa_identity["certificate_pem"],
                "aws_roles_anywhere_private_key": rsa_identity["private_key_pem"],
                "aws_roles_anywhere_certificate_chain": "",
                "aws_roles_anywhere_private_key_passphrase": "",
                "aws_roles_anywhere_region": "",
                "aws_roles_anywhere_session_duration": 3600,
            }
        )
        with patch(
            "aws_resources.openaev_aws_resources.build_boto3_session",
            side_effect=RolesAnywhereError("trust anchor not found"),
        ):
            with pytest.raises(RolesAnywhereError):
                collector._init_aws_session()

        collector.logger.error.assert_called_once()
        assert "IAM Roles Anywhere authentication failed" in (
            collector.logger.error.call_args.args[0]
        )


class TestDaemonConfigHints:
    """The daemon reads settings through the flattened config hints."""

    @staticmethod
    def _load(monkeypatch, **env):
        """Load the config from a clean environment plus the given overrides."""
        environ = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("COLLECTOR_", "OPENAEV_", "AWS_"))
        }
        environ.update(
            {
                "OPENAEV_URL": "http://localhost:3001",
                "OPENAEV_TOKEN": "token",
                "COLLECTOR_ID": "openaev_aws_resources",
            }
        )
        environ.update(env)
        monkeypatch.setattr(os, "environ", environ)

        from aws_resources.configuration.config_loader import ConfigLoader

        return ConfigLoader().to_daemon_config()

    def test_credentials_mode_is_exposed_by_default(self, monkeypatch):
        configuration = self._load(monkeypatch, COLLECTOR_AWS_ACCESS_KEY_ID="AKIA_TEST")
        assert configuration.get("aws_auth_type") == AUTH_TYPE_CREDENTIALS
        assert configuration.get("aws_access_key_id") == "AKIA_TEST"

    def test_roles_anywhere_settings_are_exposed(self, monkeypatch, rsa_identity):
        configuration = self._load(
            monkeypatch,
            COLLECTOR_AWS_AUTH_TYPE=AUTH_TYPE_ROLES_ANYWHERE,
            COLLECTOR_AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN=TRUST_ANCHOR_ARN,
            COLLECTOR_AWS_ROLES_ANYWHERE_PROFILE_ARN=PROFILE_ARN,
            COLLECTOR_AWS_ROLES_ANYWHERE_ROLE_ARN=ROLE_ARN,
            COLLECTOR_AWS_ROLES_ANYWHERE_CERTIFICATE=rsa_identity["certificate_pem"],
            COLLECTOR_AWS_ROLES_ANYWHERE_PRIVATE_KEY=rsa_identity["private_key_pem"],
            COLLECTOR_AWS_ROLES_ANYWHERE_SESSION_DURATION="7200",
        )
        assert configuration.get("aws_auth_type") == AUTH_TYPE_ROLES_ANYWHERE
        assert configuration.get("aws_roles_anywhere_trust_anchor_arn") == (
            TRUST_ANCHOR_ARN
        )
        assert configuration.get("aws_roles_anywhere_profile_arn") == PROFILE_ARN
        assert configuration.get("aws_roles_anywhere_role_arn") == ROLE_ARN
        assert configuration.get("aws_roles_anywhere_session_duration") == 7200

    def test_escaped_newline_pem_survives_the_config_round_trip(
        self, monkeypatch, rsa_identity
    ):
        """Certificates supplied through env vars keep their escaped newlines."""
        configuration = self._load(
            monkeypatch,
            COLLECTOR_AWS_AUTH_TYPE=AUTH_TYPE_ROLES_ANYWHERE,
            COLLECTOR_AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN=TRUST_ANCHOR_ARN,
            COLLECTOR_AWS_ROLES_ANYWHERE_PROFILE_ARN=PROFILE_ARN,
            COLLECTOR_AWS_ROLES_ANYWHERE_ROLE_ARN=ROLE_ARN,
            COLLECTOR_AWS_ROLES_ANYWHERE_CERTIFICATE=rsa_identity[
                "certificate_pem"
            ].replace("\n", "\\n"),
            COLLECTOR_AWS_ROLES_ANYWHERE_PRIVATE_KEY=rsa_identity[
                "private_key_pem"
            ].replace("\n", "\\n"),
        )

        signer = RolesAnywhereSigner(
            certificate_pem=normalize_pem(
                configuration.get("aws_roles_anywhere_certificate")
            ),
            private_key_pem=normalize_pem(
                configuration.get("aws_roles_anywhere_private_key")
            ),
            trust_anchor_arn=configuration.get("aws_roles_anywhere_trust_anchor_arn"),
            profile_arn=configuration.get("aws_roles_anywhere_profile_arn"),
            role_arn=configuration.get("aws_roles_anywhere_role_arn"),
        )
        assert signer.region == "eu-west-1"

    def test_invalid_auth_type_is_rejected_at_load_time(self, monkeypatch):
        with pytest.raises(ValidationError, match="aws_auth_type must be one of"):
            self._load(monkeypatch, COLLECTOR_AWS_AUTH_TYPE="mtls")
