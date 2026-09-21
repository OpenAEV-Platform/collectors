import argparse
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import requests
from OAEV_utils.release_utils import closeRelease

logging.basicConfig(encoding="utf-8", level=logging.INFO)

parser = argparse.ArgumentParser("release")
parser.add_argument(
    "branch_collectors", help="The new version number of the release.", type=str
)
parser.add_argument(
    "previous_version", help="The previous version number of the release.", type=str
)
parser.add_argument(
    "new_version", help="The new version number of the release.", type=str
)
parser.add_argument(
    "github_token", help="The github token to use for the release note.", type=str
)
args = parser.parse_args()

previous_version = args.previous_version
new_version = args.new_version
branch_collectors = args.branch_collectors
github_token = args.github_token

github_api_url = "https://api.github.com/repos/OpenAEV-Platform/collectors"
github_headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {github_token}",
    "X-GitHub-Api-Version": "2022-11-28",
}


def github_request(method: str, url: str, **kwargs: Any) -> requests.Response:
    try:
        response = requests.request(
            method,
            url,
            headers=github_headers,
            timeout=30,
            **kwargs,
        )
        response.raise_for_status()
    except requests.RequestException:
        logging.exception(
            "[collectors] GitHub API request failed: %s %s",
            method,
            url,
        )
        raise

    return response


def github_request_json(
    method: str,
    url: str,
    *,
    required_fields: tuple[str, ...],
    **kwargs: Any,
) -> dict[str, Any]:
    response = github_request(method, url, **kwargs)

    try:
        data = response.json()
    except ValueError:
        logging.exception(
            "[collectors] GitHub API returned invalid JSON: %s %s",
            method,
            url,
        )
        raise

    if not isinstance(data, dict):
        raise RuntimeError(
            f"GitHub API returned an unexpected payload for {method} {url}"
        )

    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        raise RuntimeError(
            "GitHub API response is missing required fields "
            f"{missing_fields} for {method} {url}"
        )

    return data

os.environ["DRONE_COMMIT_AUTHOR"] = "Filigran-Automation"
os.environ["GIT_AUTHOR_NAME"] = "Filigran Automation"
os.environ["GIT_AUTHOR_EMAIL"] = "automation@filigran.io"
os.environ["GIT_COMMITTER_NAME"] = "Filigran Automation"
os.environ["GIT_COMMITTER_EMAIL"] = "automation@filigran.io"

# Collectors Python

logging.info("[collectors] Starting the release")
logging.info("[collectors] Searching and replacing all version numbers everywhere")

# OpenAEV Platform >= x.x.x -> README.md
readme_version_pattern = re.compile(
    r"^(?P<prefix>.*OpenAEV Platform\s*>=\s*)"
    r"(?P<version>\d+(?:\.\d+)+)"
    r"(?P<suffix>.*)$",
    re.MULTILINE,
)

# pyoaev = "x.x.x" -> pyproject.toml
pyoaev_dependency_pattern = re.compile(
    r'^(?P<prefix>[ \t]*pyoaev[ \t]*=[ \t]*")'
    r'(?P<version>[^"]+)'
    r'(?P<suffix>"[^\r\n]*)$',
    re.MULTILINE,
)

# [project] version = "x.x.x" -> pyproject.toml
project_version_pattern = re.compile(
    r"(?P<prefix>"
    r"^\[project\][ \t]*$\r?\n"
    r"(?:(?!^\[).)*?"
    r'^[ \t]*version[ \t]*=[ \t]*"'
    r")"
    r'(?P<version>[^"]+)'
    r'(?P<suffix>"[^\r\n]*)',
    re.MULTILINE | re.DOTALL,
)


def replace_version(
    content: str,
    pattern: re.Pattern[str],
    file_path: Path,
    label: str,
) -> str:
    def replace_match(match: re.Match[str]) -> str:
        current_version = match.group("version")
        if current_version == new_version:
            return match.group(0)

        logging.info(
            "[collectors] Updated %s in %s from %s to %s",
            label,
            file_path,
            current_version,
            new_version,
        )
        return f'{match.group("prefix")}{new_version}{match.group("suffix")}'

    return pattern.sub(replace_match, content)


for readme_path in sorted(Path(".").glob("*/README.md")):
    with readme_path.open("r", encoding="utf-8", newline="") as file:
        content = file.read()

    updated_content = replace_version(
        content,
        readme_version_pattern,
        readme_path,
        "OpenAEV Platform requirement",
    )
    if updated_content != content:
        with readme_path.open("w", encoding="utf-8", newline="") as file:
            file.write(updated_content)

for pyproject_path in sorted(Path(".").glob("*/pyproject.toml")):
    with pyproject_path.open("r", encoding="utf-8", newline="") as file:
        content = file.read()

    updated_content = replace_version(
        content,
        project_version_pattern,
        pyproject_path,
        "project version",
    )
    updated_content = replace_version(
        updated_content,
        pyoaev_dependency_pattern,
        pyproject_path,
        "pyoaev dependency",
    )
    if updated_content != content:
        with pyproject_path.open("w", encoding="utf-8", newline="") as file:
            file.write(updated_content)

logging.info("[collectors] Pushing to " + branch_collectors)
subprocess.run(
    ["git", "commit", "-a", "-m", f"[all] Release {new_version}"],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
subprocess.run(
    ["git", "push", "origin", branch_collectors],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

logging.info("[collectors] Tagging")
subprocess.run(
    ["git", "tag", "-f", new_version],
    check=True,
)
subprocess.run(
    ["git", "push", "-f", "--tags"],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

logging.info("[collectors] Generating release")
subprocess.run(
    ["gren", "release"],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

# Modify the release note
logging.info("[collectors] Getting the current release note")
release_data = github_request_json(
    "GET",
    f"{github_api_url}/releases/latest",
    required_fields=("id", "body"),
)
if not isinstance(release_data["id"], int) or not isinstance(
    release_data["body"], str
):
    raise RuntimeError("GitHub latest release response has invalid field types")
release_body = release_data["body"]

logging.info("[collectors] Generating the new release note")
github_release_note_data = github_request_json(
    "POST",
    f"{github_api_url}/releases/generate-notes",
    required_fields=("body",),
    json={"tag_name": new_version, "previous_tag_name": previous_version},
)
if not isinstance(github_release_note_data["body"], str):
    raise RuntimeError("GitHub generated release notes response has an invalid body")
github_release_note_data_body = github_release_note_data["body"]
if "Full Changelog" not in release_body:
    new_release_note = (
        release_body
        + "\n"
        + github_release_note_data_body.replace(
            "## What's Changed", "#### Pull Requests:\n"
        ).replace("## New Contributors", "#### New Contributors:\n")
    )
else:
    new_release_note = release_body

logging.info("[collectors] Updating the release")
github_request(
    "PATCH",
    f"{github_api_url}/releases/{release_data['id']}",
    json={"body": new_release_note},
)

closeRelease(
    github_api_url,
    new_version,
    github_token,
)

logging.info("[collectors] Release done!")
