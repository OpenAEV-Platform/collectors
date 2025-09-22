import argparse
import logging
import os

import requests
from OBAS_utils.release_utils import closeRelease

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
parser.add_argument(
    "--dev", help="Flag to prevent pushing the release.", action="store_false"
)
args = parser.parse_args()

previous_version = args.previous_version
new_version = args.new_version
branch_collectors = args.branch_collectors
github_token = args.github_token

os.environ["DRONE_COMMIT_AUTHOR"] = "Filigran-Automation"
os.environ["GIT_AUTHOR_NAME"] = "Filigran Automation"
os.environ["GIT_AUTHOR_EMAIL"] = "automation@filigran.io"
os.environ["GIT_COMMITTER_NAME"] = "Filigran Automation"
os.environ["GIT_COMMITTER_EMAIL"] = "automation@filigran.io"

# Collectors Python

logging.info("[collectors] Starting the release")
logging.info("[collectors] Searching and replacing all version numbers everywhere")

# __version__ -> mwdb.py & __init__.py
os.system(
    "grep -rli '__version__ = "
    + previous_version
    + "' * | xargs -i@ sed -i 's/__version__ = "
    + previous_version.replace(".", "\\.")
    + "/__version__ = "
    + new_version.replace(".", "\\.")
    + "/g' @"
)

# -> README.md
os.system(
    "grep -rli 'OpenBAS Platform >= "
    + previous_version
    + "' * | xargs -i@ sed -i 's/OpenBAS Platform >= "
    + previous_version.replace(".", "\\.")
    + "/OpenBAS Platform >= "
    + new_version.replace(".", "\\.")
    + "/g' @"
)

# pyoaev= = x.x.x -> pyproject.toml
os.system(
    "grep -rli 'pyoaev = \""
    + previous_version
    + "\"' **/pyproject.toml | xargs -i@ sed -i 's/pyoaev = \""
    + previous_version.replace(".", "\\.")
    + '"/pyoaev = "'
    + new_version.replace(".", "\\.")
    + "\"/g' @"
)

os.system(
    "grep -rli 'version = \""
    + previous_version
    + "\"' **/pyproject.toml | xargs -i@ sed -i 's/version = \""
    + previous_version.replace(".", "\\.")
    + '"/version = "'
    + new_version.replace(".", "\\.")
    + "\"/g' @"
)

logging.info("[collectors] Pushing to " + branch_collectors)
os.system(
    'git commit -a -m "[all] Release '
    + new_version
    + '" > /dev/null 2>&1 && git push origin '
    + branch_collectors
    + " > /dev/null 2>&1"
)

logging.info("[collectors] Tagging")
os.system("git tag -f " + new_version + " && git push -f --tags > /dev/null 2>&1")

logging.info("[collectors] Generating release")
os.system("gren release > /dev/null 2>&1")

# Modify the release note
logging.info("[collectors] Getting the current release note")
release = requests.get(
    "https://api.github.com/repos/OpenBAS-Platform/collectors/releases/latest",
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
)
release_data = release.json()
release_body = release_data["body"]

logging.info("[collectors] Generating the new release note")
github_release_note = requests.post(
    "https://api.github.com/repos/OpenBAS-Platform/collectors/releases/generate-notes",
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
    json={"tag_name": new_version, "previous_tag_name": previous_version},
)
github_release_note_data = github_release_note.json()
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
requests.patch(
    "https://api.github.com/repos/OpenBAS-Platform/collectors/releases/"
    + str(release_data["id"]),
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
    json={"body": new_release_note},
)

closeRelease(
    "https://api.github.com/repos/OpenBAS-Platform/collectors",
    new_version,
    github_token,
)

logging.info("[collectors] Release done!")
