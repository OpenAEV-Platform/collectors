from urllib.parse import urlparse

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

    def get_attachment_filepaths(self, json_file_path):
        parent_path = "/".join(json_file_path.rsplit("/")[:-1])
        folder_content = self.repo.get_contents(parent_path)
        attachment_filepaths = [
            contentfile.path
            for contentfile in folder_content
            if contentfile.path != json_file_path
        ]
        return attachment_filepaths

    def get_attachment_download_url(self, attachment_filepath):
        content = self.repo.get_contents(attachment_filepath)
        # content.url for API url
        # content.content for the actual data
        return content.download_url
