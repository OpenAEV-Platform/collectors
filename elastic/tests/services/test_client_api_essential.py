"""Essential tests for Elastic Security Client API service."""

from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr
from requests import Session
from src.services.client_api import ElasticClientAPI
from src.services.exception import (
    ElasticAPIError,
    ElasticAuthenticationError,
    ElasticValidationError,
)
from src.services.models import ElasticSearchCriteria
from tests.services.fixtures.factories import TestDataFactory, create_test_config

PARENT_PROCESS_NAME = (
    "oaev-implant-12345678-1234-1234-1234-123456789abc"
    "-agent-87654321-4321-4321-4321-cba987654321"
)


class TestElasticClientAPIEssential:
    """Essential test cases for ElasticClientAPI.

    Tests the core functionality of the Elastic Security client API including
    initialization, session creation, query building, and fetching operations.
    """

    def test_init_with_valid_config(self):
        """Test that ElasticClientAPI initializes correctly with valid config.

        Verifies that the client properly initializes with configuration values,
        creates a session with authentication, and sets connection parameters.
        """
        config = create_test_config()

        client = ElasticClientAPI(config=config)

        assert client.config == config  # noqa: S101
        assert client.base_url == str(config.elastic.base_url).rstrip("/")  # noqa: S101
        assert client.username == config.elastic.username  # noqa: S101
        assert (  # noqa: S101
            client.password == config.elastic.password.get_secret_value()
        )
        assert isinstance(client.session, Session)  # noqa: S101

    def test_init_without_config_raises_error(self):
        """Test that initialization without config raises a validation error."""
        with pytest.raises(ElasticValidationError):
            ElasticClientAPI(config=None)

    def test_create_session_with_credentials(self):
        """Test session creation with username/password.

        Verifies that the HTTP session is configured with basic authentication
        credentials and JSON content type when no API key is provided.
        """
        config = create_test_config()

        client = ElasticClientAPI(config=config)

        expected_auth = (
            config.elastic.username,
            config.elastic.password.get_secret_value(),
        )
        assert client.session.auth == expected_auth  # noqa: S101
        assert (  # noqa: S101
            client.session.headers["Content-Type"] == "application/json"
        )

    def test_create_session_with_api_key(self):
        """Test session creation with an API key.

        Verifies that when an API key is configured it is used as the
        Authorization header and basic auth is not set.
        """
        config = create_test_config()
        config.elastic.api_key = SecretStr("my-api-key")

        client = ElasticClientAPI(config=config)

        assert (  # noqa: S101
            client.session.headers["Authorization"] == "ApiKey my-api-key"
        )
        assert client.session.auth is None  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_detection_success(self, mock_post):
        """Test successful signature fetching for a detection expectation.

        Verifies that detection expectations fetch Elastic Security alerts
        and return proper ElasticAlert objects.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = TestDataFactory.create_api_response_data()
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "detection")

        assert len(result) == 2  # noqa: S101
        assert all(hasattr(alert, "time") for alert in result)  # noqa: S101
        assert all(hasattr(alert, "src_ip") for alert in result)  # noqa: S101
        mock_post.assert_called_once()

    @patch("requests.Session.post")
    def test_fetch_signatures_with_ip_addresses(self, mock_post):
        """Test fetching signatures with source and target IP addresses.

        Verifies that IP-based signatures are converted to an Elasticsearch
        terms query on ECS ``source.ip`` and ``destination.ip`` fields.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = TestDataFactory.create_api_response_data()
        mock_post.return_value = mock_response

        search_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.1.100"},
            {"type": "target_ipv4_address", "value": "10.0.0.50"},
        ]

        result = client.fetch_signatures(search_signatures, "detection")

        assert len(result) == 2  # noqa: S101
        body = mock_post.call_args.kwargs["json"]
        query_string = body["query"]["bool"]["must"][0]["query_string"]["query"]
        assert "192.168.1.100" in query_string  # noqa: S101
        assert "10.0.0.50" in query_string  # noqa: S101
        assert "source.ip:" in query_string  # noqa: S101
        assert "destination.ip:" in query_string  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_uses_configured_index(self, mock_post):
        """Test that the configured alerts index is used in the search endpoint."""
        config = create_test_config()
        config.elastic.alerts_index = "custom-index"
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hits": {"hits": []}}
        mock_post.return_value = mock_response

        client.fetch_signatures(
            TestDataFactory.create_expectation_signatures(), "detection"
        )

        endpoint = mock_post.call_args.args[0]
        assert "/custom-index/_search" in endpoint  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_authentication_error(self, mock_post):
        """Test handling of authentication errors.

        Verifies that 401 HTTP responses are converted to
        ElasticAuthenticationError exceptions.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(ElasticAuthenticationError):
            client.fetch_signatures(search_signatures, "detection")

    @patch("requests.Session.post")
    def test_fetch_signatures_no_data_returns_empty(self, mock_post):
        """Test behavior when no alerts are found.

        Verifies that when Elasticsearch returns no hits, the method
        returns an empty list without errors.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hits": {"hits": []}}
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "detection")

        assert result == []  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_signatures_exception_handling(self, mock_post, mock_sleep):
        """Test exception handling in fetch_signatures.

        Verifies that repeated API errors are caught and wrapped in
        ElasticAPIError with a descriptive error message.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_post.side_effect = Exception("Network Error")

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(ElasticAPIError) as exc_info:
            client.fetch_signatures(search_signatures, "detection")

        assert "All Elastic Security fetch attempts failed." in str(  # noqa: S101
            exc_info.value
        )

    def test_build_query_with_ips(self):
        """Test query building with IP addresses.

        Verifies that search criteria containing IPs are converted to a
        valid Elasticsearch terms query with a time-window range filter.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_criteria = ElasticSearchCriteria(
            source_ips=["192.168.1.100"],
            target_ips=["10.0.0.50"],
        )

        query = client._build_query(search_criteria)

        bool_query = query["query"]["bool"]
        query_string = bool_query["must"][0]["query_string"]["query"]
        assert "192.168.1.100" in query_string  # noqa: S101
        assert "10.0.0.50" in query_string  # noqa: S101
        assert "source.ip:" in query_string  # noqa: S101
        assert "destination.ip:" in query_string  # noqa: S101
        gte = bool_query["filter"][0]["range"]["@timestamp"]["gte"]
        assert gte.startswith("now-")  # noqa: S101

    def test_build_query_with_parent_process_name(self):
        """Test query building with a parent process name.

        Verifies that parent process names are converted to a ``url.path``
        match_phrase clause with the injected executable-payload path.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_criteria = ElasticSearchCriteria(
            source_ips=["192.168.1.100"],
            parent_process_names=[PARENT_PROCESS_NAME],
        )

        query = client._build_query(search_criteria)

        query_string = query["query"]["bool"]["must"][0]["query_string"]["query"]
        assert "/api/injects/" in query_string  # noqa: S101
        assert "executable-payload" in query_string  # noqa: S101

    def test_default_query_template_used_when_unset(self):
        """No configured template falls back to the built-in default."""
        from src.services.client_api import DEFAULT_QUERY_TEMPLATE

        config = create_test_config()
        config.elastic.query_template = None
        client = ElasticClientAPI(config=config)
        assert client.query_template == DEFAULT_QUERY_TEMPLATE  # noqa: S101

    def test_custom_query_template_used_and_rendered(self):
        """A configured template overrides the default and is rendered."""
        config = create_test_config()
        config.elastic.query_template = "host.ip:({source_ips})"
        client = ElasticClientAPI(config=config)
        assert client.query_template == "host.ip:({source_ips})"  # noqa: S101

        query = client._build_query(ElasticSearchCriteria(source_ips=["192.0.2.20"]))
        query_string = query["query"]["bool"]["must"][0]["query_string"]["query"]
        assert query_string == 'host.ip:("192.0.2.20")'  # noqa: S101

    def test_invalid_query_template_placeholder_raises(self):
        """An unknown placeholder is rejected at initialization."""
        config = create_test_config()
        config.elastic.query_template = "host.ip:({not_a_placeholder})"
        with pytest.raises(ElasticValidationError):
            ElasticClientAPI(config=config)

    def test_empty_signatures_render_no_match_token(self):
        """Empty criteria render the no-match sentinel, never invalid syntax."""
        from src.services.client_api import NO_MATCH_TOKEN

        config = create_test_config()
        client = ElasticClientAPI(config=config)
        query = client._build_query(ElasticSearchCriteria())
        query_string = query["query"]["bool"]["must"][0]["query_string"]["query"]
        assert NO_MATCH_TOKEN in query_string  # noqa: S101

    @patch("requests.Session.post")
    def test_drilldown_recovers_implant_marker(self, mock_post):
        """The source-event drilldown recovers the implant marker.

        Detection alerts drop the process ancestry; the drilldown into the
        events index must recover the ``oaev-implant-<inject>-agent-<agent>``
        marker from the (parent) process command line so correlation can be
        deterministic.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        marker = (
            "oaev-implant-0ef06748-10db-4ad0-b718-5b02f169407b"
            "-agent-a7dbf250-e41f-461a-830c-fc93704ed8d2"
        )
        event_response = Mock()
        event_response.status_code = 200
        event_response.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "process": {
                                "name": "powershell.exe",
                                "parent": {
                                    "command_line": (
                                        f'"C:\\...\\{marker}.exe" --inject-id '
                                        "0ef06748-10db-4ad0-b718-5b02f169407b"
                                    )
                                },
                            }
                        }
                    }
                ]
            }
        }
        mock_post.return_value = event_response

        result = client._fetch_source_event_marker("host-a", 1556)

        assert result == marker  # noqa: S101

    @patch("requests.Session.post")
    def test_drilldown_climbs_ancestry_to_recover_marker(self, mock_post):
        """The drilldown walks up the process tree to find the implant marker.

        When the implant is not the alerting process's direct parent (e.g.
        implant -> cmd.exe -> reg.exe), the marker lives two hops up. The
        drilldown must climb the ancestry by ``process.entity_id`` to recover it,
        otherwise a genuine detection is wrongly left uncredited.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        marker = (
            "oaev-implant-24d1a5a3-f006-446f-b3fd-0ec94d9cb23b"
            "-agent-883d26c4-314d-4f40-abb5-b52f05dcc6ce"
        )
        # Seed event: the flagged reg.exe. No marker on itself or its direct
        # parent (cmd.exe); it only exposes the parent entity_id to climb to.
        reg_event = Mock()
        reg_event.status_code = 200
        reg_event.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "process": {
                                "name": "reg.exe",
                                "command_line": "reg export HKLM\\sam ...",
                                "entity_id": "E-reg",
                                "parent": {
                                    "name": "cmd.exe",
                                    "command_line": "cmd /c reg export HKLM\\sam",
                                    "entity_id": "E-cmd",
                                },
                            }
                        }
                    }
                ]
            }
        }
        # Ancestor event (cmd.exe): its parent IS the implant -> marker present.
        cmd_event = Mock()
        cmd_event.status_code = 200
        cmd_event.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "process": {
                                "name": "cmd.exe",
                                "entity_id": "E-cmd",
                                "parent": {
                                    "name": f"{marker}.exe",
                                    "entity_id": "E-imp",
                                },
                            }
                        }
                    }
                ]
            }
        }
        mock_post.side_effect = [reg_event, cmd_event]

        result = client._fetch_source_event_marker("host-b", 8592, "E-reg")

        assert result == marker  # noqa: S101
        # Second query must select the parent by entity_id (reuse-safe), not pid.
        second_body = mock_post.call_args_list[1].kwargs["json"]
        filters = second_body["query"]["bool"]["filter"]
        assert {"term": {"process.entity_id": "E-cmd"}} in filters  # noqa: S101

    @patch("src.services.client_api.time.sleep", lambda _s: None)
    @patch.object(ElasticClientAPI, "_execute_query")
    def test_retry_waits_for_a_matching_alert(self, mock_exec):
        """The retry loop keeps going until a *matching* alert appears.

        A non-empty but non-matching fetch (e.g. only a concurrent inject's
        alerts) must not end the retries: detection latency for this inject's own
        alert has to be absorbed, otherwise it is marked Not Detected too early.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        not_mine = [Mock(name="concurrent-inject-alert")]
        mine = [Mock(name="my-alert")]
        mock_exec.side_effect = [not_mine, not_mine, mine]

        result = client._execute_query_with_retry(
            ElasticSearchCriteria(),
            max_retries=5,
            offset_seconds=0,
            match_check=lambda alerts: alerts is mine,
        )

        assert result is mine  # noqa: S101
        assert mock_exec.call_count == 3  # retried past the two non-matching batches

    @patch("src.services.client_api.time.sleep", lambda _s: None)
    @patch.object(ElasticClientAPI, "_execute_query")
    def test_retry_returns_last_batch_when_never_matches(self, mock_exec):
        """Budget exhausted with no match -> return the last alerts (Not Detected)."""
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        not_mine = [Mock(name="other")]
        mock_exec.return_value = not_mine

        result = client._execute_query_with_retry(
            ElasticSearchCriteria(),
            max_retries=2,
            offset_seconds=0,
            match_check=lambda _alerts: False,
        )

        assert result is not_mine  # noqa: S101
        assert mock_exec.call_count == 3  # initial + 2 retries

    @patch("requests.Session.post")
    def test_pid_seed_disambiguates_reuse_by_alert_time(self, mock_post):
        """A pid-only seed picks the instance live at the alert time.

        PowerShell ScriptBlock alerts carry a pid but no entity_id, and a pid is
        reused across process lifetimes. The nearest instance (sorted @timestamp
        desc, at/just-before the alert) must win, so the recovered marker belongs
        to the process that fired the alert - not a later reuse by another inject.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        target = (
            "oaev-implant-11111111-1111-1111-1111-111111111111"
            "-agent-22222222-2222-2222-2222-222222222222"
        )
        other = (
            "oaev-implant-33333333-3333-3333-3333-333333333333"
            "-agent-22222222-2222-2222-2222-222222222222"
        )
        # pid 5056 shared by two powershell instances (desc by time): the nearest
        # (E-A) is parented by the target implant, an older reuse (E-B) by another.
        seed = Mock()
        seed.status_code = 200
        seed.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "process": {
                                "name": "powershell.exe",
                                "pid": 5056,
                                "entity_id": "E-A",
                                "parent": {
                                    "name": f"{target}.exe",
                                    "entity_id": "E-imp-t",
                                },
                            }
                        }
                    },
                    {
                        "_source": {
                            "process": {
                                "name": "powershell.exe",
                                "pid": 5056,
                                "entity_id": "E-B",
                                "parent": {
                                    "name": f"{other}.exe",
                                    "entity_id": "E-imp-o",
                                },
                            }
                        }
                    },
                ]
            }
        }
        mock_post.return_value = seed

        result = client._fetch_source_event_marker(
            "host-a", 5056, None, "2026-09-23T09:35:57.000Z"
        )
        assert result == target  # noqa: S101

    @patch("requests.Session.post")
    def test_drilldown_fallback_credits_unique_host_implant(self, mock_post):
        """Broken ancestry chain -> fall back to the sole implant on the host.

        When an intermediate process event is missing (the entity_id climb
        dead-ends), the drilldown falls back to a host + time-window lookup and
        credits the alert iff exactly one implant lineage is present.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        marker = (
            "oaev-implant-cf3e83ec-5be9-4d91-97ca-31f53c09625d"
            "-agent-883d26c4-314d-4f40-abb5-b52f05dcc6ce"
        )
        # Seed event (reg.exe): no marker, and its parent entity is not indexed.
        seed = Mock()
        seed.status_code = 200
        seed.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "process": {
                                "name": "reg.exe",
                                "entity_id": "E-reg",
                                "parent": {"name": "cmd.exe", "entity_id": "E-missing"},
                            }
                        }
                    }
                ]
            }
        }
        # Climb: parent entity not found (empty) -> chain broken.
        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"hits": {"hits": []}}
        # Fallback: exactly one implant lineage on the host in the window.
        fallback = Mock()
        fallback.status_code = 200
        fallback.json.return_value = {
            "hits": {"hits": [{"_source": {"process": {"name": f"{marker}.exe"}}}]}
        }
        mock_post.side_effect = [seed, empty, fallback]

        result = client._fetch_source_event_marker(
            "host-b", 8592, "E-reg", "2026-09-22T15:56:47.978Z"
        )
        assert result == marker  # noqa: S101

    @patch("requests.Session.post")
    def test_drilldown_fallback_declines_when_ambiguous(self, mock_post):
        """Two implant lineages on the host -> fallback abstains (no guess).

        A same-host ambiguity must never be cross-attributed: with two distinct
        injects' implants in the window the fallback returns no marker.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        seed = Mock()
        seed.status_code = 200
        seed.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "process": {
                                "name": "reg.exe",
                                "entity_id": "E-reg",
                                "parent": {"name": "cmd.exe", "entity_id": "E-missing"},
                            }
                        }
                    }
                ]
            }
        }
        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"hits": {"hits": []}}
        m1 = "oaev-implant-cf3e83ec-5be9-4d91-97ca-31f53c09625d-agent-883d26c4-314d-4f40-abb5-b52f05dcc6ce"
        m2 = "oaev-implant-dbacc661-0f2c-4013-ba56-f117419ebf90-agent-883d26c4-314d-4f40-abb5-b52f05dcc6ce"
        ambiguous = Mock()
        ambiguous.status_code = 200
        ambiguous.json.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"process": {"name": f"{m1}.exe"}}},
                    {"_source": {"process": {"name": f"{m2}.exe"}}},
                ]
            }
        }
        mock_post.side_effect = [seed, empty, ambiguous]

        result = client._fetch_source_event_marker(
            "host-b", 8592, "E-reg", "2026-09-22T15:56:47.978Z"
        )
        assert result is None  # noqa: S101

    @patch("requests.Session.post")
    def test_drilldown_returns_none_without_source_event(self, mock_post):
        """No matching source event yields no marker (drilldown is best-effort)."""
        config = create_test_config()
        client = ElasticClientAPI(config=config)
        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"hits": {"hits": []}}
        mock_post.return_value = empty

        assert client._fetch_source_event_marker("host-a", 4242) is None  # noqa: S101

    def test_build_query_time_window_extension(self):
        """Test that retries widen the query time window.

        Verifies that increasing ``extend_end_seconds`` produces a different
        (larger) time window in the range filter.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_criteria = ElasticSearchCriteria(source_ips=["192.168.1.100"])

        query1 = client._build_query(search_criteria, extend_end_seconds=0)
        query2 = client._build_query(search_criteria, extend_end_seconds=30)

        gte1 = query1["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"]
        gte2 = query2["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"]
        assert gte1 != gte2  # noqa: S101

    def test_build_search_criteria_from_signatures(self):
        """Test building search criteria from a signature list.

        Verifies that various signature types are extracted and converted
        to an ElasticSearchCriteria object.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.1.100"},
            {"type": "target_ipv6_address", "value": "2001:db8::1"},
            {"type": "parent_process_name", "value": PARENT_PROCESS_NAME},
            {"type": "start_date", "value": "2024-01-01T00:00:00Z"},
            {"type": "end_date", "value": "2024-01-01T23:59:59Z"},
        ]

        criteria = client._build_search_criteria(search_signatures)

        assert criteria.source_ips == ["192.168.1.100"]  # noqa: S101
        assert criteria.target_ips == ["2001:db8::1"]  # noqa: S101
        assert criteria.parent_process_names == [PARENT_PROCESS_NAME]  # noqa: S101
        assert criteria.start_date == "2024-01-01T00:00:00Z"  # noqa: S101
        assert criteria.end_date == "2024-01-01T23:59:59Z"  # noqa: S101

    def test_prevention_expectation_not_supported(self):
        """Test that prevention expectations raise a validation error.

        Verifies that Elastic Security rejects prevention expectation types
        as it only supports detection expectations.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(ElasticValidationError) as exc_info:
            client.fetch_signatures(search_signatures, "prevention")

        assert "Invalid expectation_type" in str(exc_info.value)  # noqa: S101

    def test_parent_process_uuid_extraction(self):
        """Test UUID extraction from parent process names.

        Verifies that UUIDs are extracted from parent process names and
        converted to a URL path search query.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        uuids = client.parent_process_parser.extract_uuids_from_parent_process_name(
            PARENT_PROCESS_NAME
        )

        assert uuids is not None  # noqa: S101
        inject_uuid, agent_uuid = uuids
        assert inject_uuid == "12345678-1234-1234-1234-123456789abc"  # noqa: S101
        assert agent_uuid == "87654321-4321-4321-4321-cba987654321"  # noqa: S101
