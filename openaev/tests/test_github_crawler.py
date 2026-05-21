import unittest
from unittest.mock import MagicMock, patch, sentinel

import openaev.github_crawler as module


def test_extract_from_url_prefix():
    default_url_prefix = (
        "https://raw.githubusercontent.com/OpenAEV-Platform/payloads/refs/heads/main/"
    )

    repo, ref = module.extract_from_url_prefix(default_url_prefix)

    assert repo == "OpenAEV-Platform/payloads"
    assert ref == "heads/main"


@patch.object(module, "Github")
class TestGithubCrawler(unittest.TestCase):
    def test_github_crawler_init(self, m_github):
        repo_name = sentinel.repo_name
        ref_value = sentinel.ref_value

        crawler = module.GithubCrawler(repo_name, ref_value)

        self.assertEqual(crawler.repo_name, sentinel.repo_name)
        self.assertEqual(crawler.ref_value, sentinel.ref_value)
        self.assertEqual(crawler.github_client, m_github.return_value)
        self.assertEqual(crawler.repo, m_github.return_value.get_repo.return_value)
        self.assertEqual(
            crawler.ref,
            m_github.return_value.get_repo.return_value.get_git_ref.return_value,
        )
        m_github.return_value.get_repo.assert_called_with(sentinel.repo_name)
        m_github.return_value.get_repo.return_value.get_git_ref.assert_called_with(
            sentinel.ref_value
        )

    @patch.object(module, "requests")
    def test_get_json_file_paths(self, m_requests, m_github):
        repo_name = sentinel.repo_name
        ref_value = sentinel.ref_value
        m_github.return_value.get_repo.return_value.trees_url = (
            "https://dead/beef{/sha}"
        )
        m_github.return_value.get_repo.return_value.get_git_ref.return_value.object.sha = (
            "feedc0de"
        )
        m_requests.get.return_value.json.return_value = {
            "tree": [
                {"path": "manifest.json"},
                {"path": ".secrets/data.json"},
                {"path": "malware/malicious/evil/payload.json"},
                {"path": "malware/not-a-json.doc"},
            ]
        }

        crawler = module.GithubCrawler(repo_name, ref_value)

        json_file_paths = crawler.get_json_file_paths()

        m_requests.get.assert_called_with("https://dead/beef/feedc0de?recursive=true")
        self.assertEqual(json_file_paths, ["malware/malicious/evil/payload.json"])

    @patch.object(module, "orjson")
    def test_get_json(self, m_orjson, m_github):
        repo_name = sentinel.repo_name
        ref_value = sentinel.ref_value
        content = MagicMock()
        m_github.return_value.get_repo.return_value.get_contents.return_value = content

        crawler = module.GithubCrawler(repo_name, ref_value)

        json_file_path = "malware/malicious/evil/payload.json"

        data = crawler.get_json(json_file_path)

        m_github.return_value.get_repo.return_value.get_contents.assert_called_with(
            "malware/malicious/evil/payload.json"
        )
        m_orjson.loads.assert_called_with(content.decoded_content)
        self.assertEqual(data, m_orjson.loads.return_value)

    def test_get_filepath_if_exists(self, m_github):
        repo_name = sentinel.repo_name
        ref_value = sentinel.ref_value
        content1 = MagicMock(path="malware/malicious/evil/payload.json")
        content2 = MagicMock(path="malware/malicious/evil/legit.docx")
        m_github.return_value.get_repo.return_value.get_contents.return_value = [
            content1, content2,
        ]

        crawler = module.GithubCrawler(repo_name, ref_value)

        folderpath = "malware/malicious/evil"
        filename = "payload.json"

        filepath = crawler.get_filepath_if_exists(folderpath, filename)

        self.assertEqual(filepath, "malware/malicious/evil/payload.json")

        filename = "wrong_filename.json"

        filepath = crawler.get_filepath_if_exists(folderpath, filename)

        self.assertIsNone(filepath)

    def test_gen_raw_download_url(self, m_github):
        repo_name = "repo/name"
        ref_value = "heads/main"

        crawler = module.GithubCrawler(repo_name, ref_value)

        path = "malware/malicious/evil/payload.json"

        raw_url = crawler.gen_raw_download_url(path)

        self.assertEqual(raw_url, "https://raw.githubusercontent.com/repo/name/heads/main/malware/malicious/evil/payload.json")
