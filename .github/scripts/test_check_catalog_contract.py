"""Unit tests for check_catalog_contract.py (run by the detect-test-files job).

python -m unittest discover -s .github/scripts -p "test_*.py"
"""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import check_catalog_contract as contract

SETTINGS = """\
from pydantic import AliasChoices, BaseModel, Field


class _Source(BaseModel):
    api_key: str = Field(alias="ACME_API_KEY")
    region: str = Field(default="eu")


class _ConfigLoaderOAEV(BaseModel):
    url: str


class ConfigLoader(BaseModel):
    openaev: _ConfigLoaderOAEV
    source: _Source = Field(validation_alias=AliasChoices("SOURCE", "COLLECTOR_ACME"))
"""

CLIENT = """\
ALLOWED_PLACEHOLDERS = {"source_ips", "start_date"}
"""


def _catalog(properties: dict) -> dict:
    return {
        "contracts": [
            {"slug": "openaev_acme", "config_schema": {"properties": properties}}
        ]
    }


class CollectorTree:
    """A throw-away collector directory with a manifest and Python sources."""

    def __init__(self, root: Path, slug: str = "openaev_acme", **sources: str):
        self.path = root / "acme"
        (self.path / "src").mkdir(parents=True)
        (self.path / "manifest-metadata.json").write_text(json.dumps({"slug": slug}))
        for name, content in sources.items():
            (self.path / "src" / f"{name}.py").write_text(content, encoding="utf-8")


class CheckCollectorTest(unittest.TestCase):
    def _check(self, properties: dict, **sources: str):
        sources = sources or {"settings": SETTINGS, "client": CLIENT}
        with tempfile.TemporaryDirectory() as tmp:
            tree = CollectorTree(Path(tmp), **sources)
            contracts = {c["slug"]: c for c in _catalog(properties)["contracts"]}
            return contract.check_collector(tree.path, contracts)

    def test_settings_read_by_alias_nested_name_or_base_are_accepted(self):
        errors, notes = self._check(
            {
                "OPENAEV_URL": {"type": "string"},  # pyoaev base setting
                "ACME_API_KEY": {"type": "string"},  # explicit alias
                "COLLECTOR_ACME_REGION": {"type": "string"},  # nested <section>_<field>
                "SOURCE_API_KEY": {"type": "string"},  # nested through a field alias
            }
        )
        self.assertEqual(errors, [])
        self.assertIn("acme: OK (4 catalog settings)", notes)

    def test_setting_unknown_to_the_collector_is_an_error(self):
        errors, _ = self._check({"ACME_LEGACY_TOKEN": {"type": "string"}})
        self.assertEqual(len(errors), 1)
        self.assertIn("'ACME_LEGACY_TOKEN' is not read by the collector", errors[0])

    def test_placeholder_rejected_by_the_collector_is_an_error(self):
        errors, _ = self._check(
            {
                "ACME_API_KEY": {
                    "type": "string",
                    "default": "ip IN ({source_ips}) url IN ({implant_urls})",
                }
            }
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("['implant_urls']", errors[0])
        self.assertIn("openaev_acme", errors[0])

    def test_former_default_the_collector_still_accepts_passes(self):
        client = CLIENT + (
            "LEGACY_DEFAULT_QUERY_TEMPLATES = (\n"
            '    "ip IN ({source_ips}) "\n'
            '    "url IN ({implant_urls})",\n'
            ")\n"
        )
        errors, notes = self._check(
            {
                "ACME_API_KEY": {
                    "type": "string",
                    "default": "ip IN ({source_ips})\n  url IN ({implant_urls})",
                }
            },
            settings=SETTINGS,
            client=client,
        )
        self.assertEqual(errors, [])
        self.assertTrue(any("former default" in note for note in notes))

    def test_allowed_placeholders_pass(self):
        errors, _ = self._check(
            {"ACME_API_KEY": {"type": "string", "default": "{source_ips} {start_date}"}}
        )
        self.assertEqual(errors, [])

    def test_placeholders_are_skipped_without_allowed_placeholders(self):
        errors, notes = self._check(
            {"ACME_API_KEY": {"type": "string", "default": "{anything}"}},
            settings=SETTINGS,
        )
        self.assertEqual(errors, [])
        self.assertTrue(any("no ALLOWED_PLACEHOLDERS" in note for note in notes))

    def test_collector_without_catalog_entry_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = CollectorTree(Path(tmp), slug="openaev_other", settings=SETTINGS)
            errors, notes = contract.check_collector(tree.path, {})
        self.assertEqual(errors, [])
        self.assertIn("no catalog entry", notes[0])

    def test_test_sources_do_not_count_as_read_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = CollectorTree(Path(tmp), settings=SETTINGS)
            (tree.path / "tests").mkdir()
            (tree.path / "tests" / "test_x.py").write_text(
                'KEY = "ACME_LEGACY_TOKEN"\n'
            )
            contracts = {
                "openaev_acme": _catalog({"ACME_LEGACY_TOKEN": {}})["contracts"][0]
            }
            errors, _ = contract.check_collector(tree.path, contracts)
        self.assertEqual(len(errors), 1)


class PlaceholdersTest(unittest.TestCase):
    def test_top_level_names(self):
        self.assertEqual(
            contract.placeholders("a {x} b {y.attr} c {z[0]} {x}"), {"x", "y", "z"}
        )

    def test_unbalanced_braces_yield_nothing(self):
        self.assertEqual(contract.placeholders("broken {"), set())


class MainTest(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = contract.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_exit_code_reflects_violations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = CollectorTree(root, settings=SETTINGS, client=CLIENT)
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps(_catalog({"ACME_GONE": {}})))
            code, out, _ = self._run(["--catalog", str(catalog), str(tree.path)])
            self.assertEqual(code, 1)
            self.assertIn("::error::acme: catalog setting 'ACME_GONE'", out)

            catalog.write_text(json.dumps(_catalog({"ACME_API_KEY": {}})))
            code, out, _ = self._run(["--catalog", str(catalog), str(tree.path)])
            self.assertEqual(code, 0)

    def test_unreadable_catalog_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = self._run(
                ["--catalog", str(Path(tmp) / "missing.json"), "acme"]
            )
        self.assertEqual(code, 2)
        self.assertIn("Could not load the OpenAEV catalog", err)

    def test_nothing_to_check(self):
        code, out, _ = self._run(["--catalog", "unused.json"])
        self.assertEqual(code, 0)
        self.assertIn("No collector to check.", out)


class ChangedCollectorsTest(unittest.TestCase):
    @staticmethod
    def _git(root: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    def test_only_collectors_touched_since_the_base_are_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._git(root, "init", "-q", "-b", "main")
            self._git(root, "config", "user.email", "ci@example.com")
            self._git(root, "config", "user.name", "ci")
            self._git(root, "config", "commit.gpgsign", "false")
            for name in ("alpha", "beta"):
                (root / name).mkdir()
                (root / name / "manifest-metadata.json").write_text("{}")
            (root / ".github").mkdir()
            (root / ".github" / "x.yml").write_text("a")
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "base")
            self._git(root, "checkout", "-q", "-b", "pr")
            (root / "beta" / "new.py").write_text("x = 1\n")
            (root / ".github" / "x.yml").write_text("b")
            (root / "README.md").write_text("top-level file")
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "change")

            changed = contract.changed_collectors("main", root)

        self.assertEqual([path.name for path in changed], ["beta"])


if __name__ == "__main__":
    unittest.main()
