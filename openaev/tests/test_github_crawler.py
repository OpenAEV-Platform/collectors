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

    @patch.object(module, "b64decode")
    @patch.object(module, "orjson")
    def test_get_json(self, m_orjson, m_b64decode, m_github):
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
        m_b64decode.assert_called_with(content.content)
        m_orjson.loads.assert_called_with(m_b64decode.return_value)
        self.assertEqual(data, m_orjson.loads.return_value)

    def test_get_attachment_filepaths(self, m_github):
        repo_name = sentinel.repo_name
        ref_value = sentinel.ref_value
        contentfile1 = MagicMock()
        contentfile1.path = "malware/malicious/evil/payload.json"
        contentfile2 = MagicMock()
        contentfile2.path = "malware/malicious/evil/legit_document.docx"
        m_github.return_value.get_repo.return_value.get_contents.return_value = [
            contentfile1,
            contentfile2,
        ]

        crawler = module.GithubCrawler(repo_name, ref_value)

        json_file_path = "malware/malicious/evil/payload.json"

        attachment_filepaths = crawler.get_attachment_filepaths(json_file_path)

        m_github.return_value.get_repo.return_value.get_contents.assert_called_with(
            "malware/malicious/evil"
        )
        self.assertEqual(
            attachment_filepaths, ["malware/malicious/evil/legit_document.docx"]
        )

    def test_get_attachment_download_url(self, m_github):
        repo_name = sentinel.repo_name
        ref_value = sentinel.ref_value
        content = MagicMock()
        content.download_url = sentinel.download_url
        m_github.return_value.get_repo.return_value.get_contents.return_value = content

        crawler = module.GithubCrawler(repo_name, ref_value)

        attachment_filepath = "malware/malicious/evil/legit_document.docx"
        download_url = crawler.get_attachment_download_url(attachment_filepath)

        m_github.return_value.get_repo.return_value.get_contents.assert_called_with(
            attachment_filepath
        )
        self.assertEqual(download_url, sentinel.download_url)
