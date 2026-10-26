"""Reading a channel's pointer and a release's files from the GitHub REST API."""

import threading
import time

import pytest
import requests
from tests.fake_github import Answer, FakeGitHub, fake_github

from scenarios.github import CALL_THREAD, GitHubSource, SourceError

REPOSITORY = "OpenAEV-Platform/scenarios"
TOKEN = "github-token-for-tests"
RELEASE_PATH = f"/repos/{REPOSITORY}/releases/tags/2026.10.27.1"
POINTER_PATH = f"/repos/{REPOSITORY}/contents/edge.json?ref=channels"


def _source(fake: FakeGitHub, token: str | None = TOKEN) -> GitHubSource:
    return GitHubSource(
        f"http://127.0.0.1:{fake.port}", REPOSITORY, token, require_https=False
    )


def _asset(fake: FakeGitHub, number: int, name: str, size: int) -> dict[str, object]:
    url = f"http://127.0.0.1:{fake.port}/repos/{REPOSITORY}/releases/assets/{number}"
    return {"name": name, "size": size, "url": url}


def test_the_pointer_is_read_raw_with_the_token() -> None:
    with fake_github() as fake:
        fake.raw(POINTER_PATH, b'{"pointer": 1}')

        assert _source(fake).pointer("edge") == b'{"pointer": 1}'

        host, path, authorization, accept = fake.asked[0]
        assert (path, authorization, accept) == (
            POINTER_PATH,
            f"Bearer {TOKEN}",
            "application/vnd.github.raw+json",
        )


def test_no_pointer_yet_is_none_and_no_token_sends_none() -> None:
    with fake_github() as fake:
        assert _source(fake, token=None).pointer("edge") is None
        assert fake.asked[0][2] is None


def test_a_pointer_over_its_bound_is_refused() -> None:
    with fake_github() as fake:
        fake.raw(POINTER_PATH, b"x" * 4097)
        with pytest.raises(SourceError, match="over 4096 bytes"):
            _source(fake).pointer("edge")


def test_the_assets_of_a_release_are_listed_by_name() -> None:
    with fake_github() as fake:
        fake.json(RELEASE_PATH, {"assets": [_asset(fake, 1, "manifest.json", 8)]})

        assets = _source(fake).assets("2026.10.27.1")

        assert {name: asset.size for name, asset in assets.items()} == {
            "manifest.json": 8
        }


@pytest.mark.parametrize(
    "document",
    [
        {"assets": "x"},
        {"assets": [{"name": "a"}]},
        {"assets": [{"name": "a", "size": "1", "url": "u"}]},
    ],
)
def test_a_release_not_as_github_gives_it_is_refused(document: object) -> None:
    with fake_github() as fake:
        fake.json(RELEASE_PATH, document)
        with pytest.raises(SourceError, match="not as GitHub gives"):
            _source(fake).assets("2026.10.27.1")


def test_a_release_named_twice_by_an_asset_is_refused() -> None:
    with fake_github() as fake:
        fake.json(
            RELEASE_PATH,
            {"assets": [_asset(fake, 1, "a.zip", 1), _asset(fake, 2, "a.zip", 1)]},
        )
        with pytest.raises(SourceError, match="twice"):
            _source(fake).assets("2026.10.27.1")


def test_an_asset_is_downloaded_through_its_redirect_without_the_token() -> None:
    with fake_github() as fake:
        storage = f"http://localhost:{fake.port}/storage/1"
        fake.redirect(f"/repos/{REPOSITORY}/releases/assets/1", storage)
        fake.raw("/storage/1", b"archive")
        fake.json(RELEASE_PATH, {"assets": [_asset(fake, 1, "a.zip", 7)]})
        source = _source(fake)

        data = source.download(source.assets("2026.10.27.1")["a.zip"], limit=100)

        assert data == b"archive"
        api, storage_asked = fake.asked[1], fake.asked[2]
        assert (api[2], api[3]) == (f"Bearer {TOKEN}", "application/octet-stream")
        assert storage_asked[0] == f"localhost:{fake.port}"
        assert storage_asked[2] is None


def test_a_download_over_its_limit_is_refused() -> None:
    with fake_github() as fake:
        fake.raw(f"/repos/{REPOSITORY}/releases/assets/1", b"x" * 101)
        fake.json(RELEASE_PATH, {"assets": [_asset(fake, 1, "a.zip", 101)]})
        source = _source(fake)

        with pytest.raises(SourceError, match="over 100 bytes"):
            source.download(source.assets("2026.10.27.1")["a.zip"], limit=100)


def test_too_many_redirects_are_refused() -> None:
    with fake_github() as fake:
        hops = f"/repos/{REPOSITORY}/releases/assets/10"
        for hop in range(7):
            fake.redirect(
                f"{hops}{hop}", f"http://127.0.0.1:{fake.port}{hops}{hop + 1}"
            )
        fake.json(
            RELEASE_PATH,
            {
                "assets": [
                    {
                        "name": "a.zip",
                        "size": 1,
                        "url": f"http://127.0.0.1:{fake.port}{hops}0",
                    }
                ]
            },
        )
        source = _source(fake)

        with pytest.raises(SourceError, match="redirect"):
            source.download(source.assets("2026.10.27.1")["a.zip"], limit=100)


def test_a_redirect_off_https_is_refused_when_https_is_required() -> None:
    with fake_github() as fake:
        source = GitHubSource(f"https://127.0.0.1:{fake.port}", REPOSITORY, TOKEN)

        with pytest.raises(SourceError, match="HTTPS"):
            source.follow(
                "http://127.0.0.1/x", limit=10, accept="application/octet-stream"
            )


def test_a_server_error_is_refused_without_the_token_in_its_message() -> None:
    with fake_github() as fake:
        fake.raw(POINTER_PATH, b"oops", status=500)
        with pytest.raises(SourceError) as refused:
            _source(fake).pointer("edge")
        assert "500" in str(refused.value)
        assert TOKEN not in str(refused.value)


def test_an_api_url_without_https_is_refused() -> None:
    with pytest.raises(SourceError, match="HTTPS"):
        GitHubSource("http://api.github.com", REPOSITORY, TOKEN)


def test_an_asset_served_outside_the_release_s_assets_is_refused() -> None:
    with fake_github() as fake:
        fake.json(
            RELEASE_PATH,
            {
                "assets": [
                    {
                        "name": "a.zip",
                        "size": 1,
                        "url": f"http://127.0.0.1:{fake.port}/x",
                    }
                ]
            },
        )
        with pytest.raises(SourceError, match="served elsewhere"):
            _source(fake).assets("2026.10.27.1")


def test_a_release_answer_not_strict_json_is_refused() -> None:
    with fake_github() as fake:
        fake.raw(RELEASE_PATH, b'{"assets": [], "assets": []}')
        with pytest.raises(SourceError, match="a key twice"):
            _source(fake).assets("2026.10.27.1")


def test_a_redirect_without_its_location_is_refused() -> None:
    with fake_github() as fake:
        fake.answers[POINTER_PATH] = Answer(302)
        with pytest.raises(SourceError, match="redirects nowhere"):
            _source(fake).pointer("edge")


class _Redirected:
    status_code = 302
    headers = {"Location": "http://storage.example/x"}

    def __enter__(self) -> "_Redirected":
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Redirecting:
    def send(self, request: object, **_: object) -> _Redirected:
        return _Redirected()


def test_a_redirect_hop_off_https_is_refused_when_https_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = requests.Session()
    monkeypatch.setattr(session, "get_adapter", lambda url: _Redirecting())
    source = GitHubSource("https://api.example", REPOSITORY, TOKEN, session=session)
    with pytest.raises(SourceError, match="storage.example/x is not served over HTTPS"):
        source.pointer("edge")


def test_an_answer_that_trickles_is_cut_at_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scenarios.github.DOWNLOAD_DEADLINE", 1)
    with fake_github() as fake:
        fake.answers[POINTER_PATH] = Answer(body=b"x" * 100, trickle=0.05)
        started = time.monotonic()

        with pytest.raises(SourceError, match="took over 1 seconds"):
            _source(fake).pointer("edge")

        assert time.monotonic() - started < 3


def test_an_asset_url_that_is_not_an_asset_number_is_refused() -> None:
    with fake_github() as fake:
        sneaky = (
            f"http://127.0.0.1:{fake.port}/repos/{REPOSITORY}/releases/assets/../../x"
        )
        fake.json(
            RELEASE_PATH, {"assets": [{"name": "a.zip", "size": 1, "url": sneaky}]}
        )
        with pytest.raises(SourceError, match="served elsewhere"):
            _source(fake).assets("2026.10.27.1")


@pytest.mark.parametrize("status", [403, 429, 500])
def test_an_answer_refused_by_the_api_is_refused(status: int) -> None:
    with fake_github() as fake:
        fake.raw(POINTER_PATH, b"{}", status=status)
        with pytest.raises(SourceError, match=f"answered {status}"):
            _source(fake).pointer("edge")


def test_every_request_has_its_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[object] = []

    class Adapter:
        def send(self, request: object, **options: object) -> object:
            asked.append(options.get("timeout"))
            raise requests.ConnectTimeout("too slow")

    session = requests.Session()
    monkeypatch.setattr(session, "get_adapter", lambda url: Adapter())
    source = GitHubSource(
        "https://api.example", REPOSITORY, None, timeout=(3, 7), session=session
    )
    with pytest.raises(SourceError, match="ConnectTimeout"):
        source.pointer("edge")
    assert asked == [(3, 7)]


def test_headers_that_trickle_are_cut_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scenarios.github.DOWNLOAD_DEADLINE", 1)
    with fake_github() as fake:
        fake.answers[POINTER_PATH] = Answer(body=b"{}", trickle=0.05, trickle_all=True)
        started = time.monotonic()

        with pytest.raises(SourceError, match="took over 1 seconds"):
            _source(fake).pointer("edge")

        assert time.monotonic() - started < 3


def test_one_call_at_most_is_left_in_flight(monkeypatch: pytest.MonkeyPatch) -> None:
    """A call cut at its deadline keeps its thread until its connection ends: the next calls
    wait for it to end rather than pile threads and connections up."""
    monkeypatch.setattr("scenarios.github.DOWNLOAD_DEADLINE", 0.5)
    with fake_github() as fake:
        fake.answers[POINTER_PATH] = Answer(
            body=b"{}" * 20, trickle=0.05, trickle_all=True
        )
        source = _source(fake)
        before = sum(t.name == CALL_THREAD for t in threading.enumerate())

        with pytest.raises(SourceError, match="took over"):
            source.pointer("edge")
        for _ in range(3):
            with pytest.raises(SourceError, match="still in flight"):
                source.pointer("edge")

        after = sum(t.name == CALL_THREAD for t in threading.enumerate())
        assert after <= before + 1


def test_the_body_of_a_redirect_is_never_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """A redirect is followed from its headers: its body, however long or slow, is not read."""
    monkeypatch.setattr("scenarios.github.DOWNLOAD_DEADLINE", 5)
    with fake_github() as fake:
        storage = f"http://localhost:{fake.port}/storage/1"
        fake.answers[POINTER_PATH] = Answer(
            302, b"x" * 2000, {"Location": storage}, trickle=0.02
        )
        fake.raw("/storage/1", b'{"pointer": 1}')
        started = time.monotonic()

        assert _source(fake).pointer("edge") == b'{"pointer": 1}'
        assert time.monotonic() - started < 2
