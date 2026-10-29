from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from mitre_attack.configuration.config_loader import ConfigLoader
from mitre_attack.openaev_mitre import OpenAEVMitre
from pyoaev.exceptions import OpenAEVUpdateError

COLLECTOR_ID = "collector-42"


def _conflict():
    return OpenAEVUpdateError("An attack pattern upsert is already running", 409)


def _external_references(external_id):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def _stix_bundle(parent_count, child_count):
    """Builds an Enterprise ATT&CK shaped bundle where every sub-technique comes
    before its parent technique, so that sending the objects in bundle order would
    put children ahead of their parents."""
    tactics = [
        {
            "type": "x-mitre-tactic",
            "id": f"x-mitre-tactic--{index}",
            "name": f"Tactic {index}",
            "x_mitre_shortname": f"tactic-{index}",
            "description": "",
            "external_references": _external_references(f"TA{index:04d}"),
        }
        for index in range(3)
    ]
    parents = [
        {
            "type": "attack-pattern",
            "id": f"attack-pattern--parent-{index}",
            "name": f"Technique {index}",
            "description": "",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "tactic-0"}
            ],
            "external_references": _external_references(f"T{index:04d}"),
        }
        for index in range(parent_count)
    ]
    children = []
    relationships = []
    for index in range(child_count):
        parent = parents[index % parent_count]
        child_id = f"attack-pattern--child-{index}"
        children.append(
            {
                "type": "attack-pattern",
                "id": child_id,
                "name": f"Sub-technique {index}",
                "description": "",
                "external_references": _external_references(
                    f"{parent['external_references'][0]['external_id']}.{index:03d}"
                ),
            }
        )
        relationships.append(
            {
                "type": "relationship",
                "id": f"relationship--{index}",
                "relationship_type": "subtechnique-of",
                "source_ref": child_id,
                "target_ref": parent["id"],
            }
        )
    return {"objects": tactics + children + parents + relationships}


def _configuration(batch_size=None):
    environment = {
        "OPENAEV_URL": "http://localhost:8080",
        "OPENAEV_TOKEN": "super-token",
        "COLLECTOR_ID": COLLECTOR_ID,
    }
    if batch_size is not None:
        environment["COLLECTOR_BATCH_SIZE"] = str(batch_size)
    with patch.dict("os.environ", environment, clear=True):
        return ConfigLoader().to_daemon_config()


def _collector(bundle=None, batch_size=None):
    collector = OpenAEVMitre(configuration=_configuration(batch_size))
    collector.api = MagicMock()
    collector.session = MagicMock()
    collector.session.get.return_value.json.return_value = bundle or _stix_bundle(
        parent_count=150, child_count=100
    )
    return collector


def _upserted_batches(collector):
    return [call.args[0] for call in collector.api.attack_pattern.upsert.call_args_list]


class AttackPatternBatchingTest(TestCase):

    def test_attack_patterns_are_sent_in_batches_of_the_default_size(self):
        # -- PREPARE --
        collector = _collector()

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        batches = _upserted_batches(collector)
        self.assertEqual([100, 100, 50], [len(batch) for batch in batches])

    def test_attack_patterns_are_sent_in_batches_of_the_configured_size(self):
        # -- PREPARE --
        collector = _collector(batch_size=40)

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        batches = _upserted_batches(collector)
        self.assertEqual(7, len(batches))
        self.assertTrue(all(len(batch) <= 40 for batch in batches))

    def test_a_batch_size_of_0_sends_every_attack_pattern_in_one_call(self):
        # -- PREPARE --
        collector = _collector(batch_size=0)

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        batches = _upserted_batches(collector)
        self.assertEqual([250], [len(batch) for batch in batches])

    def test_a_batch_size_of_0_with_an_empty_bundle_sends_nothing(self):
        # -- PREPARE --
        collector = _collector(bundle={"objects": []}, batch_size=0)

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        collector.api.attack_pattern.upsert.assert_not_called()

    def test_every_attack_pattern_is_sent_exactly_once(self):
        # -- PREPARE --
        collector = _collector(batch_size=40)

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        sent_ids = [
            attack_pattern["attack_pattern_stix_id"]
            for batch in _upserted_batches(collector)
            for attack_pattern in batch
        ]
        expected_ids = {f"attack-pattern--parent-{index}" for index in range(150)} | {
            f"attack-pattern--child-{index}" for index in range(100)
        }
        self.assertEqual(len(expected_ids), len(sent_ids))
        self.assertEqual(expected_ids, set(sent_ids))

    def test_parents_are_sent_before_any_sub_technique(self):
        # -- PREPARE --
        collector = _collector(batch_size=40)

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        sent = [
            attack_pattern
            for batch in _upserted_batches(collector)
            for attack_pattern in batch
        ]
        has_parent = [ap["attack_pattern_parent"] is not None for ap in sent]
        first_child = has_parent.index(True)
        self.assertNotIn(False, has_parent[first_child:])

    def test_each_sub_technique_parent_is_sent_in_the_same_or_an_earlier_batch(self):
        # -- PREPARE --
        collector = _collector(batch_size=40)

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        already_sent = set()
        for batch in _upserted_batches(collector):
            already_sent |= {ap["attack_pattern_stix_id"] for ap in batch}
            for attack_pattern in batch:
                parent = attack_pattern["attack_pattern_parent"]
                if parent is not None:
                    self.assertIn(parent, already_sent)

    def test_parents_then_sub_techniques_keep_their_bundle_order(self):
        # -- PREPARE --
        bundle = _stix_bundle(parent_count=3, child_count=4)
        orphan = dict(bundle["objects"][3], id="attack-pattern--orphan")
        bundle["objects"].insert(3, orphan)
        bundle["objects"].append(
            {
                "type": "relationship",
                "id": "relationship--orphan",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--orphan",
                "target_ref": "attack-pattern--not-in-bundle",
            }
        )
        collector = _collector(bundle=bundle, batch_size=2)

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        sent_ids = [
            attack_pattern["attack_pattern_stix_id"]
            for batch in _upserted_batches(collector)
            for attack_pattern in batch
        ]
        self.assertEqual(
            [
                "attack-pattern--parent-0",
                "attack-pattern--parent-1",
                "attack-pattern--parent-2",
                "attack-pattern--orphan",
                "attack-pattern--child-0",
                "attack-pattern--child-1",
                "attack-pattern--child-2",
                "attack-pattern--child-3",
            ],
            sent_ids,
        )


class BatchFailureTest(TestCase):

    def test_a_failing_batch_stops_the_import(self):
        # -- PREPARE --
        collector = _collector()
        collector.api.attack_pattern.upsert.side_effect = [
            None,
            RuntimeError("upsert failed"),
            None,
        ]

        # -- EXECUTE --
        with self.assertRaises(RuntimeError):
            collector._process_message()

        # -- ASSERT --
        self.assertEqual(2, collector.api.attack_pattern.upsert.call_count)


@patch("time.sleep")
class ConflictRetryTest(TestCase):

    def test_a_batch_rejected_by_a_running_import_is_retried_until_accepted(
        self, sleep
    ):
        # -- PREPARE --
        collector = _collector()
        collector.api.attack_pattern.upsert.side_effect = [
            None,
            _conflict(),
            _conflict(),
            None,
            None,
        ]
        collector.logger = MagicMock()

        # -- EXECUTE --
        collector._process_message()

        # -- ASSERT --
        batches = _upserted_batches(collector)
        self.assertEqual([100, 100, 100, 100, 50], [len(batch) for batch in batches])
        self.assertEqual(batches[1], batches[2])
        self.assertEqual(batches[1], batches[3])
        self.assertEqual([call(10), call(20)], sleep.call_args_list)
        self.assertEqual(2, collector.logger.warning.call_count)

    def test_a_batch_still_rejected_after_5_attempts_stops_the_import(self, sleep):
        # -- PREPARE --
        collector = _collector()
        collector.api.attack_pattern.upsert.side_effect = [None] + [
            _conflict() for _ in range(5)
        ]

        # -- EXECUTE --
        with self.assertRaises(OpenAEVUpdateError):
            collector._process_message()

        # -- ASSERT --
        self.assertEqual(6, collector.api.attack_pattern.upsert.call_count)
        self.assertEqual([call(10), call(20), call(40), call(80)], sleep.call_args_list)

    def test_other_platform_errors_are_not_retried(self, sleep):
        # -- PREPARE --
        collector = _collector()
        collector.api.attack_pattern.upsert.side_effect = [
            None,
            OpenAEVUpdateError("Internal error", 500),
        ]

        # -- EXECUTE --
        with self.assertRaises(OpenAEVUpdateError):
            collector._process_message()

        # -- ASSERT --
        self.assertEqual(2, collector.api.attack_pattern.upsert.call_count)
        sleep.assert_not_called()
