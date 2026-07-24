import io
import mimetypes
import zipfile

import requests

from openaev.constants import DEFAULT_EXPECTED_SECURITY_PLATFORMS
from openaev.github_crawler import GithubCrawler


class CommonProcessor:
    def __init__(
        self,
        api,
        logger,
        payload_path,
        github_crawler: GithubCrawler,
    ) -> None:
        self.api = api
        self.logger = logger
        self.payload_path = payload_path
        self.github_crawler = github_crawler

        self.session = requests.Session()

    def _create_or_get_tag(self, tag_name: str, tag_color: str = "#6b7280"):
        """Create or get a tag and return its ID."""
        try:
            tag_data = {"tag_name": tag_name, "tag_color": tag_color}
            result = self.api.tag.upsert(tag_data)
            return result.get("tag_id")
        except Exception as e:
            self.logger.warning(f"Failed to upsert tag {tag_name}: {e}")
            return None

    @staticmethod
    def _apply_default_expected_security_platforms(payload) -> None:
        """Fill in default expected security platform types on the payload.

        Only applies when the source repo JSON does not declare
        payload_expected_security_platforms itself: an explicit value always wins,
        including an explicit empty map (which means "any platform"). Defaults are
        only declared for the expectation types the payload has; payloads without
        expectations are left untouched.
        """
        if payload.get("payload_expected_security_platforms") is not None:
            return

        expected_security_platforms = {
            expectation_type: list(platform_types)
            for expectation_type, platform_types in DEFAULT_EXPECTED_SECURITY_PLATFORMS.items()
            if expectation_type in (payload.get("payload_expectations") or [])
        }

        if expected_security_platforms:
            payload["payload_expected_security_platforms"] = expected_security_platforms

    def _process_payload_tags(self, payload: dict):
        tags_mapping = {}
        payload_tags = payload.get("payload_tags", [])
        for tag in payload_tags:
            tag = {
                key: value
                for key, value in tag.items()
                if key in ["tag_id", "tag_name", "tag_color"]
            }
            new_tag = self.api.tag.upsert(tag)
            tags_mapping[tag["tag_id"]] = new_tag["tag_id"]

        new_tags = [
            tags_mapping[tag["tag_id"]]
            for tag in payload_tags
            if tag["tag_id"] in tags_mapping
        ]

        # Add collector source tag
        source_tag_name = "source:openaev-datasets"
        source_tag_id = self._create_or_get_tag(source_tag_name, "#ef4444")  # Red
        if source_tag_id and source_tag_id not in new_tags:
            new_tags.append(source_tag_id)

        # Add native/community tag if applicable
        if payload.get("native_collection", False):
            native_tag_name = "type:native"
            native_tag_id = self._create_or_get_tag(native_tag_name, "#10b981")  # Green
            if native_tag_id and native_tag_id not in new_tags:
                new_tags.append(native_tag_id)

        return tags_mapping, new_tags

    def _process_payload_attack_patterns(self, payload: dict) -> list:
        attack_patterns = payload.get("payload_attack_patterns", [])

        for idx in range(len(attack_patterns)):
            if "id" in attack_patterns[idx]:
                del attack_patterns[idx]["id"]
            if "type" in attack_patterns[idx]:
                del attack_patterns[idx]["type"]

        if len(attack_patterns) > 0:
            self.api.attack_pattern.upsert(attack_patterns, True)

        attack_patterns = [
            attack["attack_pattern_external_id"] for attack in attack_patterns
        ]
        return attack_patterns

    def _process_document(self, payload: dict, document_key: str, tags_mapping: dict):
        payload_document = payload.get(document_key, {})

        if "id" in payload_document:
            del payload_document["id"]
        if "type" in payload_document:
            del payload_document["type"]
        if payload_document.get("document_tags", []):
            if payload_document["document_tags"] and isinstance(
                payload_document["document_tags"][0], dict
            ):
                payload_document["document_tags"] = [
                    tag["tag_id"] for tag in payload_document.get("document_tags", [])
                ]

        if not payload_document.get("document_path", "") and payload_document.get(
            "document_target"
        ):
            folderpath = self.payload_path.rsplit("/", 1)[0]
            filename = payload_document.get("document_target")
            filepath = self.github_crawler.get_filepath_if_exists(folderpath, filename)
            if filepath:
                payload_document["document_path"] = filepath
            else:
                self.logger.warning(
                    f"Failed to find document {filename} for payload {self.payload_path}"
                )

        if not payload_document.get("document_name", "") and payload_document.get(
            "document_target"
        ):
            payload_document["document_name"] = payload_document["document_target"]

        if not payload_document.get("document_path", ""):
            return payload_document, None

        # Upload the document
        payload_document["document_tags"] = [
            tags_mapping[tag_id]
            for tag_id in payload_document.get("document_tags", [])
            if tag_id in tags_mapping
        ]

        url = self.github_crawler.gen_raw_download_url(
            payload_document["document_path"]
        )
        if payload_document["document_path"].endswith(".zip"):
            target = payload_document["document_target"]
            zip_response = self.session.get(url)
            zip_response.raise_for_status()
            with io.BytesIO(zip_response.content) as zip_buffer:
                with zipfile.ZipFile(zip_buffer) as z:
                    if not target in z.namelist():
                        raise Exception(f"No {target} file found in zip at {url}")
                    with z.open(target, pwd=b"infected") as unzipped_file:
                        file_content = unzipped_file.read()
        else:
            file_response = self.session.get(url)
            file_response.raise_for_status()
            file_content = file_response.content

        mime_type, _ = mimetypes.guess_type(payload_document["document_name"])
        mime_type = mime_type or "application/octet_stream"
        with io.BytesIO(file_content) as file_handle:
            file = (
                payload_document["document_name"],
                file_handle,
                mime_type,
            )
            new_document = self.api.document.upsert(
                document=payload_document, file=file
            )

        return payload_document, new_document

    def _process_payload(self, payload: dict) -> dict:
        raise NotImplementedError()
