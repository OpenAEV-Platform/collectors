"""A fake OpenAEV platform on a local port: it answers what a test gives it, and records each
call it receives with its path, its Authorization header and the parts of its body."""

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass(frozen=True)
class Part:
    name: str
    filename: str | None
    data: bytes


@dataclass(frozen=True)
class Call:
    path: str
    authorization: str | None
    parts: tuple[Part, ...]


@dataclass
class FakePlatform:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    calls: list[Call] = field(default_factory=list)
    port: int = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def answer(self, document: object, status: int = 200) -> None:
        self.status, self.body = status, json.dumps(document).encode()
        self.headers = {"Content-Type": "application/json"}


def _parts(content_type: str, body: bytes) -> tuple[Part, ...]:
    message = BytesParser(policy=HTTP).parsebytes(
        f"Content-Type: {content_type}\r\n\r\n".encode() + body
    )
    if not message.is_multipart():
        return ()
    parts = []
    for part in message.iter_parts():
        data = part.get_payload(decode=True)
        parts.append(
            Part(
                str(part.get_param("name", header="content-disposition")),
                part.get_filename(),
                data if isinstance(data, bytes) else b"",
            )
        )
    return tuple(parts)


@contextmanager
def fake_platform() -> Iterator[FakePlatform]:
    fake = FakePlatform()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - the name http.server calls
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            fake.calls.append(
                Call(
                    self.path,
                    self.headers.get("Authorization"),
                    _parts(self.headers.get("Content-Type", ""), body),
                )
            )
            self.send_response(fake.status)
            for name, value in fake.headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(fake.body)))
            self.end_headers()
            self.wfile.write(fake.body)

        def log_message(self, *arguments: object) -> None:
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
