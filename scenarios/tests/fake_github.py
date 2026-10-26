"""A fake GitHub REST API on a local port, serving what a test gives it and recording what
it is asked, with which token."""

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Answer:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    trickle: float = 0.0  # seconds between two bytes of the body, to answer slowly
    trickle_all: bool = False  # the status line and headers too, not only the body


@dataclass
class FakeGitHub:
    answers: dict[str, Answer] = field(default_factory=dict)
    asked: list[tuple[str, str, str | None, str | None]] = field(default_factory=list)
    port: int = 0

    def json(self, path: str, document: object, status: int = 200) -> None:
        self.answers[path] = Answer(status, json.dumps(document).encode())

    def raw(self, path: str, body: bytes, status: int = 200) -> None:
        self.answers[path] = Answer(status, body)

    def redirect(self, path: str, location: str, status: int = 302) -> None:
        self.answers[path] = Answer(status, b"", {"Location": location})


@contextmanager
def fake_github() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the name http.server calls
            fake.asked.append(
                (
                    self.headers.get("Host", ""),
                    self.path,
                    self.headers.get("Authorization"),
                    self.headers.get("Accept"),
                )
            )
            answer = fake.answers.get(
                self.path, Answer(404, b'{"message": "Not Found"}')
            )
            if answer.trickle_all:
                head = f"HTTP/1.1 {answer.status} OK\r\nContent-Length: {len(answer.body)}\r\n\r\n"
                for byte in head.encode() + answer.body:
                    try:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                    except OSError:
                        return
                    time.sleep(answer.trickle)
                return
            self.send_response(answer.status)
            for name, value in answer.headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(answer.body)))
            self.end_headers()
            if not answer.trickle:
                self.wfile.write(answer.body)
                return
            for byte in answer.body:
                try:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(answer.trickle)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fake.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()
