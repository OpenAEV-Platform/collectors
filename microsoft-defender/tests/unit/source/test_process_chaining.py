"""Matching through evidence chaining, file evidence and drill-down (collectors#611).

Every alert below is built through the Alert model, so each case validates the
Microsoft Graph alerts v2 schema the collector reads.
"""

import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import orjson
import src.source.data_fetcher as fetcher_module
import src.source.source_handler as handler_module
from pydantic import HttpUrl
from pyoaev.apis.inject_expectation.model.expectation import Expectation
from pyoaev.client import OpenAEV
from pyoaev.signatures.types import SignatureTypes
from src.collector.engines.basic import BasicCollectorEngine
from src.collector.models.source import Source
from src.source.signatures import SUPPORTED_SIGNATURES
from src.source.source_data import Alert

IMPLANT = (
    "oaev-implant-4f46361a-a90e-46fe-96ba-a453bca9a68d"
    "-agent-294c2457-64d0-485a-b9ea-f25e2bb6005c"
)
OTHER_IMPLANT = (
    "oaev-implant-11111111-2222-3333-4444-555555555555"
    "-agent-66666666-7777-8888-9999-000000000000"
)
DEVICE = "a1b2c3d4e5f6"
HOSTNAME = "station-name-012"
EXPECTATION_SAMPLE = Path("./tests/functional/source/expectation_sample_one.json")


def _process(
    pid: int,
    ppid: int,
    image: str,
    parent_image: str,
    created: str,
    parent_created: str,
    device: str = DEVICE,
) -> dict:
    return {
        "@odata.type": "#microsoft.graph.security.processEvidence",
        "processId": pid,
        "parentProcessId": ppid,
        "processCommandLine": image,
        "processCreationDateTime": created,
        "parentProcessCreationDateTime": parent_created,
        "mdeDeviceId": device,
        "imageFile": {"fileName": image, "filePath": "C:\\Windows\\System32"},
        "parentProcessImageFile": {
            "fileName": parent_image,
            "filePath": "C:\\Windows\\System32",
        },
    }


def _file(name: str, path: str) -> dict:
    return {
        "@odata.type": "#microsoft.graph.security.fileEvidence",
        "fileDetails": {"fileName": name, "filePath": path},
    }


def _device(hostname: str = HOSTNAME) -> dict:
    return {
        "@odata.type": "#microsoft.graph.security.deviceEvidence",
        "mdeDeviceId": DEVICE,
        "deviceDnsName": hostname,
        "hostName": hostname,
    }


def _alert(title: str, evidence: list[dict]) -> Alert:
    return Alert(
        **{
            "id": "da637000000000000000_1",
            "title": title,
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "alertWebUrl": "https://security.microsoft.com/alerts/da637000000000000000_1",
            "lastActivityDateTime": "2026-11-25T21:00:00Z",
            "lastUpdateDateTime": "2026-11-25T21:01:00Z",
            "evidence": evidence,
        }
    )


def _implant_chain() -> list[dict]:
    """powershell -> implant -> cmd.exe -> reg.exe, one evidence per process."""
    return [
        _process(
            7776,
            12132,
            f"{IMPLANT}.exe",
            "powershell.exe",
            "2026-11-25T20:59:50Z",
            "2026-11-25T20:59:40Z",
        ),
        _process(
            8000,
            7776,
            "cmd.exe",
            f"{IMPLANT}.exe",
            "2026-11-25T20:59:55Z",
            "2026-11-25T20:59:50Z",
        ),
        _process(
            8100,
            8000,
            "reg.exe",
            "cmd.exe",
            "2026-11-25T20:59:56Z",
            "2026-11-25T20:59:55Z",
        ),
    ]


def _matches(alert: Alert, implant: str = IMPLANT) -> bool:
    """Run the collector's matching path for a detection expectation."""
    groups = {
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME.value: [
            {
                "type": SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME.value,
                "value": implant,
            }
        ],
        SignatureTypes.SIG_TYPE_HOSTNAME.value: [
            {"type": SignatureTypes.SIG_TYPE_HOSTNAME.value, "value": HOSTNAME}
        ],
    }
    handler = handler_module.DefenderSourceHandler
    alert_data = handler.get_alert_data_from_oaev_data(
        SUPPORTED_SIGNATURES, handler.serialize_as_oaevdata(alert)
    )
    return handler.match_signature_groups_and_alert_data(
        groups, alert_data, MagicMock()
    )


class TestProcessChaining(unittest.TestCase):
    def test_child_tool_with_parent_chain_to_the_implant_matches(self):
        """reg.exe whose ancestry (cmd.exe, then the implant) is in the alert matches."""
        alert = _alert(
            "Anomaly detected in ASEP registry", [*_implant_chain(), _device()]
        )
        self.assertIn(f"{IMPLANT}.exe", alert.chained_process_names())
        self.assertTrue(_matches(alert))

    def test_reg_exe_alone_with_cmd_parent_does_not_match(self):
        """reg.exe under cmd.exe, nothing reaching the implant: no false positive."""
        alert = _alert(
            "Anomaly detected in ASEP registry",
            [
                _process(
                    8100,
                    8000,
                    "reg.exe",
                    "cmd.exe",
                    "2026-11-25T20:59:56Z",
                    "2026-11-25T20:59:55Z",
                ),
                _device(),
            ],
        )
        self.assertFalse(_matches(alert))

    def test_host_and_time_alone_never_match(self):
        """Only the device evidence: hostname weight stays under the threshold."""
        alert = _alert("Suspicious behavior by cmd.exe was observed", [_device()])
        self.assertFalse(_matches(alert))

    def test_chain_needs_the_same_device(self):
        """A parent id seen on another device is not an ancestor."""
        chain = _implant_chain()
        chain[0]["mdeDeviceId"] = "ffff0000ffff"
        chain[1]["parentProcessImageFile"]["fileName"] = "explorer.exe"
        alert = _alert("Anomaly detected in ASEP registry", chain[1:])
        alert_with_foreign = _alert("Anomaly detected in ASEP registry", chain)
        self.assertNotIn(f"{IMPLANT}.exe", alert.chained_process_names())
        self.assertNotIn(f"{IMPLANT}.exe", alert_with_foreign.chained_process_names())
        self.assertFalse(_matches(alert))

    def test_reused_process_id_with_another_creation_time_is_not_chained(self):
        """The parent creation time must agree with the candidate's creation time."""
        chain = _implant_chain()
        chain[0]["processCreationDateTime"] = "2026-11-25T18:00:00Z"
        chain[1]["parentProcessImageFile"]["fileName"] = "explorer.exe"
        alert = _alert("Anomaly detected in ASEP registry", chain)
        self.assertNotIn(f"{IMPLANT}.exe", alert.chained_process_names())

    def test_cycle_in_the_evidences_terminates(self):
        """Two evidences naming each other as parent: the walk stops."""
        alert = _alert(
            "Suspicious behavior by cmd.exe was observed",
            [
                _process(1, 2, "a.exe", "b.exe", "2026-11-25T20:00:00Z", None),
                _process(2, 1, "b.exe", "a.exe", "2026-11-25T20:00:00Z", None),
            ],
        )
        self.assertEqual(alert.chained_process_names(), {"a.exe", "b.exe"})

    def test_other_inject_implant_does_not_match(self):
        """The chain reaches another inject's implant: this expectation is not matched."""
        alert = _alert(
            "Anomaly detected in ASEP registry", [*_implant_chain(), _device()]
        )
        self.assertFalse(_matches(alert, implant=OTHER_IMPLANT))


class TestFileEvidence(unittest.TestCase):
    def test_file_evidence_naming_the_implant_matches(self):
        """An alert with only a file evidence naming the implant matches."""
        alert = _alert(
            "A suspicious file was observed",
            [
                _file(
                    f"{IMPLANT}.exe",
                    "C:\\Dev\\Projects\\OAEVAgent-Session\\runtimes\\execution-1",
                ),
                _device(),
            ],
        )
        self.assertTrue(_matches(alert))

    def test_file_evidence_path_containing_the_implant_matches(self):
        """The implant name in the file path counts too (relaxed substring)."""
        alert = _alert(
            "A suspicious file was observed",
            [_file("payload.ps1", f"C:\\Temp\\{IMPLANT}\\drop")],
        )
        self.assertTrue(_matches(alert))

    def test_file_evidence_without_the_implant_does_not_match(self):
        alert = _alert(
            "A suspicious file was observed",
            [_file("payload.ps1", "C:\\Temp\\drop"), _device()],
        )
        self.assertFalse(_matches(alert))


class TestInfostealerShapes(unittest.TestCase):
    """The two alert shapes of the 25 Nov 2026 infostealer simulation."""

    def _detection_expectation(self) -> Expectation:
        data = orjson.loads(EXPECTATION_SAMPLE.read_bytes())
        data["success_label"] = "Detected"
        data["failure_label"] = "Not Detected"
        data["inject_expectation_signatures"] = [
            {"type": "parent_process_name", "value": IMPLANT},
            {"type": "hostname", "value": HOSTNAME},
            {"type": "start_date", "value": "2026-11-25T20:59:00Z"},
            {"type": "end_date", "value": "2026-11-25T21:00:30Z"},
        ]
        return Expectation(**data, api_client="api-client")

    @patch.object(fetcher_module, "MSGraphAuthClient")
    @patch.object(fetcher_module.DefenderDataFetcher, "fetch_data")
    def _process_batch(self, alert: Alert, m_fetch_data, m_auth_client):
        m_fetch_data.return_value = [alert]
        source = Source(
            data_fetcher_model=fetcher_module.DefenderDataFetcher,
            source_data_model=Alert,
            signatures=SUPPORTED_SIGNATURES,
        )
        engine = BasicCollectorEngine(
            name="name",
            collector_id="collector_id",
            source=source,
            source_handler=handler_module.DefenderSourceHandler(MagicMock()),
            oaev_api=MagicMock(spec_set=OpenAEV),
        )
        config = MagicMock()
        config.retry_window = timedelta(minutes=20)
        engine.configure_engine(config)
        return engine._process_batch([self._detection_expectation()])

    def test_suspicious_file_was_observed_is_detected(self):
        alert = _alert(
            "A suspicious file was observed",
            [_file(f"{IMPLANT}.exe", "C:\\Users\\Public\\runtimes"), _device()],
        )
        results = self._process_batch(alert)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_valid)

    def test_suspicious_behavior_by_cmd_is_detected(self):
        alert = _alert(
            "Suspicious behavior by cmd.exe was observed",
            [*_implant_chain()[:2], _device()],
        )
        results = self._process_batch(alert)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_valid)


class TestDrilldown(unittest.TestCase):
    def _fetcher(self, mock_session_class, mock_auth_client):
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "token"
        mock_auth_client.return_value = mock_auth
        session = MagicMock()
        mock_session_class.return_value = session
        config = MagicMock()
        config.base_url = HttpUrl("https://graph.microsoft.com/v1.0")
        config.max_fetch_retries = 5
        return fetcher_module.DefenderDataFetcher(config), session

    def _reg_only_alert(self) -> Alert:
        return _alert(
            "Anomaly detected in ASEP registry",
            [
                _process(
                    8100,
                    8000,
                    "reg.exe",
                    "cmd.exe",
                    "2026-11-25T20:59:56Z",
                    "2026-11-25T20:59:55Z",
                ),
                _device(),
            ],
        )

    def test_alert_naming_the_implant_needs_no_drilldown(self):
        alert = _alert("Anomaly detected in ASEP registry", _implant_chain())
        self.assertFalse(fetcher_module.DefenderDataFetcher.needs_drilldown(alert))

    def test_alert_without_process_evidence_needs_no_drilldown(self):
        alert = _alert("A suspicious file was observed", [_device()])
        self.assertFalse(fetcher_module.DefenderDataFetcher.needs_drilldown(alert))

    def test_hunting_query_is_bounded_by_device_process_and_window(self):
        process = self._reg_only_alert().process_evidences()[0]
        query = fetcher_module.DefenderDataFetcher.build_hunting_query(process)
        self.assertIn("DeviceProcessEvents", query)
        self.assertIn(f'DeviceId == "{DEVICE}"', query)
        self.assertIn("ProcessId == 8100", query)
        self.assertIn("2026-11-25T20:57:56+00:00", query)
        self.assertIn("2026-11-25T21:01:56+00:00", query)
        self.assertIn("InitiatingProcessParentFileName", query)

    def test_hunting_query_refuses_an_unexpected_device_id(self):
        process = self._reg_only_alert().process_evidences()[0]
        process.mde_device_id = 'x" or 1==1'
        self.assertIsNone(
            fetcher_module.DefenderDataFetcher.build_hunting_query(process)
        )

    @patch.object(fetcher_module, "MSGraphAuthClient")
    @patch.object(fetcher_module, "Session")
    def test_drilldown_ancestors_make_the_child_tool_match(
        self, mock_session_class, mock_auth_client
    ):
        fetcher, session = self._fetcher(mock_session_class, mock_auth_client)
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "results": [
                {
                    "FileName": "reg.exe",
                    "InitiatingProcessFileName": "cmd.exe",
                    "InitiatingProcessParentFileName": f"{IMPLANT}.exe",
                }
            ]
        }
        session.post.return_value = response
        alert = self._reg_only_alert()
        self.assertFalse(_matches(alert))

        fetcher.drill_down([alert])

        session.post.assert_called_once()
        self.assertTrue(
            session.post.call_args.args[0].endswith("/security/runHuntingQuery")
        )
        self.assertTrue(_matches(alert))

    @patch.object(fetcher_module, "MSGraphAuthClient")
    @patch.object(fetcher_module, "Session")
    def test_drilldown_without_the_implant_keeps_no_match(
        self, mock_session_class, mock_auth_client
    ):
        fetcher, session = self._fetcher(mock_session_class, mock_auth_client)
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "results": [
                {
                    "InitiatingProcessFileName": "cmd.exe",
                    "InitiatingProcessParentFileName": "explorer.exe",
                }
            ]
        }
        session.post.return_value = response
        alert = self._reg_only_alert()

        fetcher.drill_down([alert])

        self.assertFalse(_matches(alert))

    @patch.object(fetcher_module, "MSGraphAuthClient")
    @patch.object(fetcher_module, "Session")
    def test_drilldown_failure_raises_instead_of_a_verdict(
        self, mock_session_class, mock_auth_client
    ):
        fetcher, session = self._fetcher(mock_session_class, mock_auth_client)
        response = MagicMock()
        response.status_code = 500
        response.raise_for_status.side_effect = fetcher_module.RequestException(
            "500 Server Error"
        )
        session.post.return_value = response

        with self.assertRaises(fetcher_module.DrilldownError):
            fetcher.drill_down([self._reg_only_alert()])

    @patch.object(fetcher_module, "MSGraphAuthClient")
    @patch.object(fetcher_module, "Session")
    def test_drilldown_without_permission_is_skipped(
        self, mock_session_class, mock_auth_client
    ):
        fetcher, session = self._fetcher(mock_session_class, mock_auth_client)
        response = MagicMock()
        response.status_code = 403
        session.post.return_value = response
        alerts = [self._reg_only_alert(), self._reg_only_alert()]

        fetcher.drill_down(alerts)

        session.post.assert_called_once()
        self.assertEqual(alerts[0].drilldown_process_names, [])

    @patch.object(fetcher_module, "MSGraphAuthClient")
    @patch.object(fetcher_module.DefenderDataFetcher, "fetch_data")
    def test_drilldown_error_postpones_the_expectation(
        self, m_fetch_data, m_auth_client
    ):
        """A failed drill-down leaves the expectation for the next cycle."""
        m_fetch_data.side_effect = fetcher_module.DrilldownError("boom")
        source = Source(
            data_fetcher_model=fetcher_module.DefenderDataFetcher,
            source_data_model=Alert,
            signatures=SUPPORTED_SIGNATURES,
        )
        engine = BasicCollectorEngine(
            name="name",
            collector_id="collector_id",
            source=source,
            source_handler=handler_module.DefenderSourceHandler(MagicMock()),
            oaev_api=MagicMock(spec_set=OpenAEV),
        )
        config = MagicMock()
        config.retry_window = timedelta(minutes=20)
        engine.configure_engine(config)
        expectation = TestInfostealerShapes()._detection_expectation()

        results = engine._process_batch([expectation])

        self.assertEqual(results, [])
