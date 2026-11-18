"""Structured wire framing and rejected inputs before any socket creation."""

import base64

import pytest
from argos.backend.core import http_transport

from test_web_transport import FakeSocket, settings


def structured(**updates):
    value: dict = settings()
    value.update(
        method="POST",
        request_version=2,
        request_headers=[
            ["content-type", "application/json"],
            ["accept", "application/json"],
        ],
        request_body=base64.b64encode("é\r\nprivate-body".encode()).decode(),
    )
    value.update(updates)
    return value


def test_structured_utf8_exact_content_length_and_no_header_injection(monkeypatch):
    peer = FakeSocket(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
    monkeypatch.setattr(http_transport.socket, "socket", lambda *_: peer)
    metadata, body = http_transport.exchange(structured())
    assert metadata["status"] == 201 and metadata["body_complete"] and body == b""
    head, payload = peer.sent.split(b"\r\n\r\n", 1)
    assert payload == "é\r\nprivate-body".encode()
    assert head.count(b"Content-Length:") == 1
    assert b"Content-Length: 16" in head
    assert head.startswith(b"POST / HTTP/1.1\r\nHost: target:80\r\n")
    assert (
        b"accept: application/json" in head
        and b"content-type: application/json" in head
    )
    assert b"Accept-Encoding: identity" in head and b"Connection: close" in head


@pytest.mark.parametrize(
    "updates",
    [
        {"request_headers": [["host", "outside"]]},
        {"request_headers": [["accept", "x\r\nX: x"]]},
        {"request_headers": [["content-length", "0"]]},
        {"request_headers": [["authorization", "private"]]},
        {"request_headers": [["cookie", "private"]]},
        {
            "request_headers": [
                ["content-type", "application/json"],
                ["content-type", "text/plain"],
            ]
        },
        {"request_headers": [["accept", "x" * 2049]]},
        {"request_headers": [["content-type", "multipart/form-data"]]},
        {"request_headers": []},
        {"request_version": True},
        {"request_version": 3},
        {"method": "CONNECT"},
        {"method": "GET"},
        {"method": "HEAD"},
        {"method": "OPTIONS"},
        {"request_body": "not base64!"},
        {"request_body": base64.b64encode(b"\xff").decode()},
        {"request_body": base64.b64encode(b"x" * 16385).decode()},
        {"request_target": "/a\r\nX: x"},
        {"host_header": "target\r\nX: x"},
    ],
)
def test_malformed_worker_input_refused_without_socket(monkeypatch, updates):
    def forbidden(*args):
        pytest.fail("Invalid structured input created a socket")

    monkeypatch.setattr(http_transport.socket, "socket", forbidden)
    metadata, body = http_transport.exchange(structured(**updates))
    assert metadata["error"] == "protocol_failed" and body == b""
    assert not metadata["body_complete"]


def test_old_worker_input_cannot_send_post(monkeypatch):
    monkeypatch.setattr(
        http_transport.socket, "socket", lambda *_: pytest.fail("Unexpected socket")
    )
    config = settings()
    config["method"] = "POST"
    metadata, _ = http_transport.exchange(config)
    assert metadata["error"] == "protocol_failed"
