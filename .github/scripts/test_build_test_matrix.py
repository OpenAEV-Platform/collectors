"""Unit tests for build_test_matrix.py (run by the detect-test-files job).

python -m unittest discover -s .github/scripts -p "test_*.py"
"""

import contextlib
import tempfile
import unittest
from pathlib import Path

import build_test_matrix as matrix

ALPINE = """\
# Common base stage for shared environment configuration.
FROM python:3.14-alpine AS base
FROM base AS builder
RUN pip install --no-cache-dir "poetry==2.3.2"
FROM base AS runner
"""

UBI9 = """\
FROM registry.access.redhat.com/ubi9/ubi-minimal AS base
RUN set -eux; \\
    microdnf -y --setopt=install_weak_deps=0 install python3.14; \\
    microdnf clean all;
FROM base AS builder
RUN set -eux; \\
    microdnf -y --setopt=install_weak_deps=0 install python3.14-pip; \\
    pip3.14 install poetry==2.3.2;
"""


class DockerfilePythonVersionsTest(unittest.TestCase):
    def test_python_base_image(self):
        self.assertEqual(matrix.dockerfile_python_versions(ALPINE), ["3.14"])

    def test_interpreter_installed_as_a_package(self):
        self.assertEqual(matrix.dockerfile_python_versions(UBI9), ["3.14"])

    def test_platform_flag_registry_prefix_and_lowercase_from(self):
        text = "from --platform=$BUILDPLATFORM docker.io/library/python:3.15-slim as base\n"
        self.assertEqual(matrix.dockerfile_python_versions(text), ["3.15"])

    def test_arg_default_is_expanded(self):
        text = (
            'ARG PYTHON_VERSION="3.15"\nFROM python:${PYTHON_VERSION}-alpine AS base\n'
        )
        self.assertEqual(matrix.dockerfile_python_versions(text), ["3.15"])

    def test_no_python_version(self):
        text = "FROM alpine:3.20\nRUN apk add python3-dev python3\nRUN pip install x\n"
        self.assertEqual(matrix.dockerfile_python_versions(text), [])

    def test_versions_are_sorted_numerically_and_deduplicated(self):
        text = "FROM python:3.14 AS a\nFROM python:3.9 AS b\nFROM python:3.14 AS c\n"
        self.assertEqual(matrix.dockerfile_python_versions(text), ["3.9", "3.14"])


class DiscoverShippedCollectorsTest(unittest.TestCase):
    @staticmethod
    def _collector(root: Path, name: str, **dockerfiles: str) -> None:
        """A collector directory: a pyproject.toml plus the given Dockerfile contents."""
        (root / name).mkdir()
        (root / name / "pyproject.toml").write_text("[project]\nname = 'x'\n")
        for filename, content in dockerfiles.items():
            (root / name / filename).write_text(content, encoding="utf-8")

    def test_one_entry_per_collector_and_image_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._collector(root, "alpha", Dockerfile=ALPINE, Dockerfile_ubi9=UBI9)
            self._collector(
                root,
                "beta",
                Dockerfile=ALPINE,
                Dockerfile_ubi9=UBI9.replace("3.14", "3.15"),
            )
            self._collector(root, "gamma")  # no Dockerfile: not shipped
            self._collector(root, "delta", Dockerfile="FROM scratch\n")
            self._collector(root, "scripts", Dockerfile=ALPINE)  # excluded dir
            self._collector(root, ".hidden", Dockerfile=ALPINE)  # dot dir

            with contextlib.chdir(root):
                entries = matrix.discover_shipped_collectors()

        self.assertEqual(
            entries,
            [
                {"name": "alpha py3.14", "collector": "alpha", "python": "3.14"},
                {"name": "beta py3.14", "collector": "beta", "python": "3.14"},
                {"name": "beta py3.15", "collector": "beta", "python": "3.15"},
                {"name": "delta", "collector": "delta", "python": ""},
            ],
        )


if __name__ == "__main__":
    unittest.main()
