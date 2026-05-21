from urllib.parse import quote, urlparse

import orjson
import requests
from github import Github


def extract_from_url_prefix(url_prefix):
    """convert the previously used url_prefix format to the new repo and ref format"""
    parsed_url = urlparse(url_prefix)
    path = parsed_url.path
    repo, ref = path.rstrip("/").lstrip("/").split("/refs/")
    return repo, ref


class GithubCrawler:
    def __init__(self, repo_name, ref_value):
        self.repo_name = repo_name
        self.ref_value = ref_value

        self.github_client = Github()
        self.repo = self.github_client.get_repo(self.repo_name)
        self.ref = self.repo.get_git_ref(self.ref_value)

    def get_json_file_paths(self):
        tree_url = self.repo.trees_url
        tree_url = tree_url.replace("{/sha}", f"/{self.ref.object.sha}")
        tree_url += "?recursive=true"

        tree_data = requests.get(tree_url).json()["tree"]

        json_file_paths = [
            element["path"]
            for element in tree_data
            if element["path"].endswith(".json")
            and element["path"] != "manifest.json"
            and not element["path"].startswith(".")
        ]
        return json_file_paths

    def get_json(self, json_file_path):
        content = self.repo.get_contents(json_file_path)
        data = content.decoded_content
        data = orjson.loads(data)
        return data

    def get_filepath_if_exists(self, folderpath, filename):
        """check if a specific file exists in a specific folder"""
        filepath = f"{folderpath.rstrip('/')}/{filename.lstrip('/')}"
        if filepath in [el.path for el in self.repo.get_contents(folderpath)]:
            return filepath
        return

    def gen_raw_download_url(self, path):
        """return the raw download URL for a specific path"""
        path = quote(path)
        url = f"https://raw.githubusercontent.com/{self.repo_name}/{self.ref_value}/{path}"
        return url
