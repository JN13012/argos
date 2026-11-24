"""Transport qualification: scripted protocol tests and opt-in owned endpoints."""

import io
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.contracts import WebBudgetUsage, WebErrorCode, WebRequest
from argos.backend.attack.web.policy import WebPolicy, WebPolicyError
from argos.backend.attack.web.resolver import WebResolver
from argos.backend.attack.web.transport import HTTPWorker, decode_frame
from argos.backend.core import http_transport
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.http_sandbox import http_command
from argos.backend.core.isolated_worker import IsolationError
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.network_worker import NetworkTools
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

real_network = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1", reason="Opt-in isolated HTTP endpoints"
)


def settings(**updates):
    return dict(
        connect_ip="127.0.0.1",
        port=80,
        tls_hostname=None,
        host_header="target:80",
        method="GET",
        request_target="/",
        timeout_ms=1000,
        body_bytes=32,
        response_header_bytes=32768,
        response_header_count=100,
        header_line_bytes=8192,
        **updates,
    )


class FakeSocket:
    def __init__(self, response):
        self.response = io.BytesIO(response)
        self.sent = b""
        self.destination = None

    def settimeout(self, value):
        assert value > 0

    def connect(self, destination):
        self.destination = destination

    def recv(self, maximum):
        return self.response.read(maximum)

    def sendall(self, value):
        self.sent += value

    def close(self):
        pass


@pytest.mark.parametrize(
    "response,error,body,complete",
    [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", None, b"abc", True),
        (
            b"HTTP/1.1 302 Found\r\nLocation: https://marker.invalid/x\r\n"
            b"Content-Length: 0\r\n\r\n",
            None,
            b"",
            True,
        ),
        (b"HTTP/1.1 200 OK\r\n\r\nabc", None, b"abc", True),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n0\r\n\r\n",
            None,
            b"abc",
            True,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n" + b"x" * 33,
            "response_limit",
            b"x" * 32,
            False,
        ),
        (b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 33, "response_limit", b"x" * 32, False),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n21\r\n" + b"x" * 33,
            "response_limit",
            b"x" * 32,
            False,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "protocol_failed",
            b"",
            False,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"
            b"Transfer-Encoding: chunked\r\n\r\nx",
            "protocol_failed",
            b"",
            False,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nbomb",
            "unsupported_encoding",
            b"",
            False,
        ),
        (b"HTTP/1.1 101 Switching\r\n\r\n", "protocol_failed", b"", False),
        (b"HTTP/1.1 100 Continue\r\n\r\n" * 7, "protocol_failed", b"", False),
        (b"HTTP/1.1 200 OK\r\n Bad: folded\r\n\r\n", "protocol_failed", b"", False),
        (
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 8192 + b"\r\n\r\n",
            "protocol_failed",
            b"",
            False,
        ),
        (
            b"HTTP/1.1 200 OK\r\n" + b"X: a\r\n" * 101 + b"\r\n",
            "protocol_failed",
            b"",
            False,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
            "protocol_failed",
            b"",
            False,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx",
            "protocol_failed",
            b"x",
            False,
        ),
    ],
)
def test_protocol_without_host_network(monkeypatch, response, error, body, complete):
    connection = FakeSocket(response)
    monkeypatch.setattr(http_transport.socket, "socket", lambda *args: connection)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: pytest.fail("Worker DNS"))
    metadata, retained = http_transport.exchange(settings())
    assert metadata["error"] == error
    assert metadata["body_complete"] is complete
    assert retained == body
    assert connection.destination == ("127.0.0.1", 80)
    assert b"Host: target:80\r\n" in connection.sent
    assert b"Accept-Encoding: identity\r\n" in connection.sent
    decoded = decode_frame(http_transport.frame(metadata, retained), 32)
    assert decoded.error == error


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data[:3],
        lambda data: data + b"suffix",
        lambda data: data[:-1],
        lambda data: struct.pack("!I", 65537) + data[4:],
        lambda data: data[:-1] + b"z",
    ],
)
def test_frame_corruption(mutate):
    frame = http_transport.frame(
        dict(status=200, headers=[], error=None, body_complete=True), b"abc"
    )
    with pytest.raises(IsolationError):
        decode_frame(mutate(frame), 32)


def plan(tmp_path, port=9090, *, tls=False, hostname="target", body_bytes=32):
    scheme = "https" if tls else "http"
    url = f"{scheme}://{hostname}:{port}/secret?token=private-value"
    config = WebMissionConfig.from_dict(
        {
            "schema_version": 2,
            "name": "HTTP qualification",
            "seeds": [url],
            "capabilities": ["http.discover"],
            "destination": {"kind": "evaluation_private", "networks": ["127.0.0.1/32"]},
            "limits": {"response_bytes": body_bytes},
        }
    )
    mission = Mission.draft(
        config.name, "owned-target", datetime.now(UTC) + timedelta(hours=1)
    )
    record = config.to_record(mission)
    key = ed25519.Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    database = tmp_path / f"{uuid4()}.db"
    with MissionStore(database) as store:
        store.create(record)
        store.activate_reviewed(
            mission.id,
            issue_offline_approval(
                record, "test", datetime.now(UTC) + timedelta(minutes=30), key
            ),
            verifier,
        )
    policy = WebPolicy(database, verifier)
    request = WebRequest(mission.id, url)
    usage = WebBudgetUsage(mission.id)
    preflight = policy.preflight(request, usage=usage)
    from argos.backend.attack.web.contracts import ResolvedWebTarget

    resolution = ResolvedWebTarget(hostname, ("127.0.0.1",), datetime.now(UTC))
    return policy.prepare(request, resolution, usage=usage), preflight


def tools():
    return NetworkTools(
        os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
        os.environ.get(
            "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
        ),
    )


@contextmanager
def server(response, context=None, delay: float = 0):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(12)
    seen = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                if context is not None:
                    connection = context.wrap_socket(connection, server_side=True)
                with connection:
                    connection.settimeout(3)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = connection.recv(8192)
                        if not chunk:
                            return
                        data += chunk
                    seen.append(data)
                    time.sleep(delay)
                    connection.sendall(response)
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], seen
    finally:
        listener.close()
        thread.join(timeout=1)


@real_network
@pytest.mark.parametrize("hostname", ["target", "other-target", "127.0.0.1"])
def test_real_pinned_http(tmp_path, monkeypatch, hostname):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:1")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:1")
    with server(
        b"HTTP/1.1 302 Found\r\nLocation: https://marker.invalid/x\r\n"
        b"Content-Length: 3\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nabc"
    ) as (port, seen):
        prepared, _ = plan(tmp_path, port, hostname=hostname)
        result = HTTPWorker(tools()).exchange(prepared, active=lambda: True)
        assert result.state == "completed", result
        assert result.body == b"abc"
        assert result.status == 302
        assert result.headers[-2:] == (("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"))
        assert len(seen) == 1
        assert f"Host: {hostname}:{port}\r\n".encode() in seen[0]
        assert b"Cookie:" not in seen[0]


def certificates(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "target")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("target")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "ca.pem"
    private = tmp_path / "key.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, private)
    names = []
    context.set_servername_callback(lambda sock, name, ctx: names.append(name))
    return ca, context, names


@real_network
@pytest.mark.parametrize(
    "hostname,trust,success",
    [
        ("target", True, True),
        ("other-target", True, False),
        ("target", False, False),
        ("127.0.0.1", True, False),
    ],
)
def test_real_tls(tmp_path, hostname, trust, success):
    ca, context, names = certificates(tmp_path)
    with server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", context) as (
        port,
        seen,
    ):
        prepared, _ = plan(tmp_path, port, tls=True, hostname=hostname)
        transport = HTTPWorker(tools(), **({"ca_bundle": str(ca)} if trust else {}))
        result = transport.exchange(prepared, active=lambda: True)
        if success:
            assert result.state == "completed", result
            assert result.body == b"ok"
            assert names == [hostname]
        else:
            assert result.error == "tls_failed", result
            assert seen == []
            if hostname == "127.0.0.1":
                assert names == [None]


@real_network
@pytest.mark.parametrize("cancelled", [False, True])
def test_stop_during_response(tmp_path, cancelled):
    with server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", delay=2) as (
        port,
        seen,
    ):
        prepared, _ = plan(tmp_path, port)
        observed = []

        def active():
            if cancelled and seen:
                if not observed:
                    observed.append(time.monotonic())
                return False
            return True

        result = HTTPWorker(tools()).exchange(
            prepared,
            active=active,
            cancel=None,
        )
        assert result.state == ("cancelled" if cancelled else "completed")
        assert len(seen) == 1
        if cancelled:
            assert time.monotonic() - observed[0] < 1


def test_resolver_literal_never_starts_process(tmp_path, monkeypatch):
    _, preflight = plan(tmp_path, hostname="127.0.0.1")
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("Literal DNS"))
    assert WebResolver().resolve(preflight).addresses == ("127.0.0.1",)


def test_supervised_system_resolver(tmp_path):
    _, preflight = plan(tmp_path, hostname="localhost")
    result = WebResolver().resolve(preflight)
    assert result.hostname == "localhost"
    assert "127.0.0.1" in result.addresses


@pytest.mark.parametrize("mode", ["timeout", "cancel", "oversize", "invalid", "error"])
def test_resolver_kills_and_reaps_child(tmp_path, monkeypatch, mode):
    _, preflight = plan(tmp_path)
    real_popen = subprocess.Popen
    children = []

    def spawn(*args, **kwargs):
        code = {
            "timeout": "import time; time.sleep(30)",
            "cancel": "import time; time.sleep(30)",
            "oversize": "print('x' * 5000)",
            "invalid": "print('{}')",
            "error": "raise SystemExit(2)",
        }[mode]
        child = real_popen(["/usr/bin/python3", "-c", code], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", spawn)
    preflight = replace(preflight, timeout_ms=100)
    started = time.monotonic()
    with pytest.raises(WebPolicyError) as error:
        WebResolver().resolve(
            preflight, active=lambda: mode != "cancel" or not children
        )
    assert error.value.code == (
        WebErrorCode.CANCELLED
        if mode == "cancel"
        else WebErrorCode.DNS_TIMEOUT
        if mode == "timeout"
        else WebErrorCode.DNS_DENIED
        if mode in ("oversize", "invalid")
        else WebErrorCode.DNS_FAILED
    )
    assert children[0].poll() is not None
    assert time.monotonic() - started < 1


def test_http_sandbox_rejects_arbitrary_entrypoint():
    with pytest.raises(RuntimeError):
        http_command(
            ["--", "/bin/sh"],
            {
                "ca": "/etc/ssl/certs/ca-certificates.crt",
                "script_sha256": "invalid",
                "ca_sha256": "invalid",
            },
        )


def test_partial_body_survives_timeout(monkeypatch):
    connection = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial")
    recv = connection.recv

    def stalled(maximum):
        data = recv(maximum)
        if not data:
            raise TimeoutError
        return data

    connection.recv = stalled
    monkeypatch.setattr(socket, "socket", lambda *args: connection)
    metadata, body = http_transport.exchange(settings())
    assert metadata["error"] == "request_timeout"
    assert body == b"partial"
    assert not metadata["body_complete"]


def test_private_input_not_in_arguments(tmp_path, monkeypatch):
    from argos.backend.core.isolated_worker import OfflineWorker, WorkerResult

    prepared, _ = plan(tmp_path)

    def capture(self, arguments, *, network, **kwargs):
        assert arguments == ("/usr/bin/python3", "-I", "/argos-http.py")
        assert "private-value" not in json.dumps(network)
        source = Path(network["http"]["input"])
        assert source.stat().st_mode & 0o077 == 0
        payload = json.loads(source.read_bytes())
        assert payload["request_target"].endswith("token=private-value")
        return WorkerResult(
            "completed",
            0,
            http_transport.frame(
                dict(status=200, headers=[], error=None, body_complete=True), b"ok"
            ),
            b"",
        )

    monkeypatch.setattr(OfflineWorker, "_run", capture)
    monkeypatch.setattr(NetworkTools, "identity", lambda self: {})
    assert HTTPWorker().exchange(prepared, active=lambda: True).body == b"ok"
    assert not list(tmp_path.glob("argos-http-*"))


@pytest.mark.parametrize(
    "tamper", [None, "input", "script", "ca", "permissions", "entrypoint"]
)
def test_fixed_mounts_and_input_verification(tmp_path, tamper):
    import hashlib
    from dataclasses import asdict

    from argos.backend.core.isolated_worker import WorkerLimits
    from argos.backend.core.worker_guardian import sandbox_command

    script = Path(http_transport.__file__)
    source = tmp_path / "request"
    source.write_bytes(b'{"private": "value"}')
    source.chmod(0o600)
    ca = Path("/etc/ssl/certs/ca-certificates.crt")
    configuration = dict(
        input=str(source),
        input_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        ca=str(ca),
        ca_sha256=hashlib.sha256(ca.read_bytes()).hexdigest(),
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
    )
    command = sandbox_command(
        asdict(WorkerLimits()), ["/usr/bin/python3", "-I", "/argos-http.py"]
    )
    if tamper in ("input", "script", "ca"):
        configuration[tamper + "_sha256"] = "0" * 64
    elif tamper == "permissions":
        source.chmod(0o644)
    elif tamper == "entrypoint":
        command[-1] = "/bin/sh"
    if tamper:
        with pytest.raises(RuntimeError):
            http_command(command, configuration)
        return
    command, descriptor = http_command(command, configuration)
    try:
        assert os.read(descriptor, 65536) == source.read_bytes()
        assert command.count("--ro-bind") <= 6
        assert "/argos-http.py" in command and "/argos-ca.pem" in command
        assert str(tmp_path) not in command
        assert "/etc" not in command
        assert "/home" not in command
    finally:
        os.close(descriptor)


@real_network
def test_real_response_deadline(tmp_path):
    with server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", delay=0.5) as (
        port,
        seen,
    ):
        prepared, _ = plan(tmp_path, port)
        prepared = replace(
            prepared, preflight=replace(prepared.preflight, timeout_ms=100)
        )
        result = HTTPWorker(tools()).exchange(prepared, active=lambda: True)
        assert result.error == "request_timeout", result
        assert not result.body_complete
        assert len(seen) == 1


@real_network
@pytest.mark.parametrize("body", [b"x" * 32, b"x" * 100000])
def test_real_bounded_body(tmp_path, body):
    with server(
        f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
    ) as (port, seen):
        prepared, _ = plan(tmp_path, port)
        result = HTTPWorker(tools()).exchange(prepared, active=lambda: True)
        assert result.body == body[:32]
        assert result.body_complete == (len(body) == 32)
        assert result.error == (None if len(body) == 32 else "response_limit")


def test_expanded_header_metadata_is_partial_and_bounded():
    metadata = dict(
        status=200, headers=[["X", "\xff" * 16000]], error=None, body_complete=True
    )
    frame = http_transport.frame(metadata, b"ok")
    result = decode_frame(frame, 32)
    assert result.error == "response_limit"
    assert result.headers == ()
    assert result.body == b"ok"
    assert not result.body_complete
    assert len(frame) < 65536


def test_total_header_limit(monkeypatch):
    connection = FakeSocket(
        b"HTTP/1.1 200 OK\r\n" + (b"X: " + b"x" * 7000 + b"\r\n") * 5 + b"\r\n"
    )
    monkeypatch.setattr(socket, "socket", lambda *args: connection)
    metadata, body = http_transport.exchange(settings())
    assert metadata["error"] == "protocol_failed"
    assert body == b""


def test_head_does_not_read_body(monkeypatch):
    connection = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
    monkeypatch.setattr(socket, "socket", lambda *args: connection)
    config = settings()
    config["method"] = "HEAD"
    metadata, body = http_transport.exchange(config)
    assert metadata["error"] is None
    assert metadata["body_complete"]
    assert body == b""


def test_cancelled_literal_does_not_resolve(tmp_path, monkeypatch):
    _, preflight = plan(tmp_path, hostname="127.0.0.1")
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("Cancelled DNS")
    )
    event = threading.Event()
    event.set()
    with pytest.raises(WebPolicyError) as error:
        WebResolver().resolve(preflight, cancel=event)
    assert error.value.code is WebErrorCode.CANCELLED


def test_tls_frame_is_bounded_and_backwards_compatible():
    metadata = dict(status=200, headers=[], error=None, body_complete=True)
    assert decode_frame(http_transport.frame(metadata, b""), 32).tls is None
    tls = dict(
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        alpn="http/1.1",
        peer_certificate_sha256="a" * 64,
    )
    assert (
        decode_frame(http_transport.frame(dict(metadata, tls=tls), b""), 32).tls == tls
    )
    for changes in [
        dict(version="OpenSSL 3.0"),
        dict(peer_certificate_sha256="secret"),
        dict(cipher="x" * 129),
        dict(issuer="private-subject"),
    ]:
        with pytest.raises(IsolationError):
            decode_frame(
                http_transport.frame(dict(metadata, tls=dict(tls, **changes)), b""), 32
            )
