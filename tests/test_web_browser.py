"""Browser mediation protocol and fail-closed boundaries, without a browser."""

import hashlib
import json
import socket
from dataclasses import replace
from pathlib import Path
from threading import Event
from unittest.mock import Mock, patch

import pytest
from argos.backend.attack.web.browser import (
    VERSION,
    BrowserInstallation,
    BrowserRelay,
    BrowserWorker,
    decode_observation,
)
from argos.backend.attack.web.transport import HTTPExchange
from argos.backend.core.browser_sandbox import browser_command, tree_digest
from argos.backend.core.isolated_worker import (
    IsolationError,
    OfflineWorker,
    WorkerLimits,
)
from argos.backend.core.worker_guardian import sandbox_command


def exchange(body=b"ok", headers=(("content-type", "text/html"),)):
    return HTTPExchange("completed", None, 200, headers, body, True)


@pytest.fixture
def relay(tmp_path):
    handler = Mock(return_value=exchange())
    value = BrowserRelay(
        str(tmp_path / "relay"), "https://fixture.test/", handler, lambda: True, None
    )
    try:
        yield value
    finally:
        value.close()


def request(
    url="https://fixture.test/path?private=secret", method="GET", resource="fetch"
):
    return {"url": url, "method": method, "resource": resource}


@pytest.mark.parametrize(
    "payload",
    [
        request("https://other.test/"),
        request("http://fixture.test/"),
        request("https://fixture.test:444/"),
        request(method="POST"),
        request(method="PUT"),
        request(resource="websocket"),
        request("file:///etc/passwd"),
        request("https://user:secret@fixture.test/"),
        request("https://fixture.test/path#frag"),
        request("https://fixture.test/\\bad"),
        {**request(), "headers": {"Authorization": "secret"}},
        [],
        {**request(), "resource": []},
        request(url="x" * 8193),
    ],
)
def test_relay_denies_without_calling_mediator(relay, payload):
    assert relay.answer(payload) == {"blocked": True}
    relay.mediator.assert_not_called()
    assert relay.limited


def test_private_request_and_cookie_removal_and_redacted_events(relay):
    relay.mediator.return_value = exchange(
        headers=(
            ("content-type", "text/html"),
            ("set-cookie", "token=secret"),
            ("content-length", "2"),
            ("connection", "close"),
        )
    )
    answer = relay.answer(request())
    assert answer["headers"] == [["content-type", "text/html"]]
    received = relay.mediator.call_args.args[0]
    assert received.url.endswith("private=secret")
    assert "secret" not in repr(received)
    assert set(vars(received)) == {"url", "method", "resource"}
    assert "secret" not in json.dumps(relay.events)
    assert relay.events[0]["state"] == "supplied"


@pytest.mark.parametrize(
    "response",
    [
        replace(exchange(), state="partial"),
        replace(exchange(), error="response_limit"),
        replace(exchange(), body_complete=False),
        replace(exchange(), status=101),
        replace(exchange(), status=302),
        exchange(b"x" * 524289),
        exchange(headers=(("content-encoding", "gzip"),)),
        exchange(headers=(("location", "/a"), ("Location", "/b"))),
        exchange(headers=(("invalid name", "x"),)),
        exchange(headers=(("content-type", "text/html\r\nInjected: x"),)),
    ],
)
def test_incomplete_or_ambiguous_resources_are_never_fulfilled(relay, response):
    relay.mediator.return_value = response
    assert relay.answer(request()) == {"blocked": True}
    assert relay.events[0]["state"] == "blocked"
    assert relay.limited


def test_request_and_aggregate_byte_budgets(relay):
    relay.body_bytes = 8 * 1024**2
    assert relay.answer(request()) == {"blocked": True}
    relay.body_bytes = 0
    relay.attempts = 64
    relay.mediator.reset_mock()
    assert relay.answer(request()) == {"blocked": True}
    relay.mediator.assert_not_called()


def test_no_resource_after_revocation_even_during_mediator(relay):
    active = Event()
    active.set()
    relay.active = active.is_set

    def revoke(req):
        active.clear()
        return exchange()

    relay.mediator.side_effect = revoke
    assert relay.answer(request()) == {"blocked": True}
    assert relay.events[0]["state"] == "blocked"
    relay.mediator.reset_mock()
    assert relay.answer(request()) == {"blocked": True}
    relay.mediator.assert_not_called()


def test_unix_protocol_fragmented_request_and_oversized_input(relay, tmp_path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(tmp_path / "relay"))
        client.sendall(b'{"url":')
        assert relay.poll()
        client.sendall(json.dumps(request())[7:].encode() + b"\n")
        assert relay.poll()
        client.settimeout(1)
        assert json.loads(client.recv(8192))["status"] == 200
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(tmp_path / "relay"))
        client.sendall(b"x" * 16385)
        assert relay.poll()
        assert relay.limited
        assert len(relay.events) == 1


def test_browser_never_combines_offline_and_network_profiles():
    with pytest.raises(IsolationError, match="cannot enable network"):
        OfflineWorker()._run(("/usr/bin/true",), browser={}, network={})


def test_cancelled_before_start_does_not_need_installation(tmp_path):
    worker = BrowserWorker(
        BrowserInstallation(tmp_path / "missing", tmp_path / "engine")
    )
    with patch.object(OfflineWorker, "_run") as forbidden:
        assert (
            worker.navigate(
                "https://fixture.test/", mediator=Mock(), active=lambda: False
            ).state
            == "cancelled"
        )
        forbidden.assert_not_called()


def test_missing_installation_fails_without_host_fallback(tmp_path):
    worker = BrowserWorker(
        BrowserInstallation(tmp_path / "missing", tmp_path / "engine")
    )
    with patch.object(OfflineWorker, "_run") as forbidden:
        with pytest.raises(IsolationError, match="installation"):
            worker.navigate(
                "https://fixture.test/", mediator=Mock(), active=lambda: True
            )
        forbidden.assert_not_called()


def test_installation_tree_hash_refuses_links_and_detects_change(tmp_path):
    (tmp_path / "a").write_text("one")
    before = tree_digest(tmp_path)
    (tmp_path / "a").write_text("two")
    assert tree_digest(tmp_path) != before
    (tmp_path / "link").symlink_to(tmp_path / "a")
    with pytest.raises(RuntimeError, match="installation entry"):
        tree_digest(tmp_path)


def test_fixed_entry_point_and_mounts_and_input_identity(tmp_path, monkeypatch):
    from argos.backend.core import browser_sandbox

    node = tmp_path / "node"
    node.write_bytes(b"synthetic Node binary")
    real_read = Path.read_bytes

    def read_bytes(path):
        return real_read(node if path == Path("/usr/bin/node") else path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    core = tmp_path / "core"
    engine = tmp_path / "engine"
    core.mkdir()
    engine.mkdir()
    source = tmp_path / "input"
    source.touch(mode=0o600)
    source.write_bytes(b"{}")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        relay = tmp_path / "relay"
        server.bind(str(relay))
        relay.chmod(0o600)
        settings = {
            "core": str(core),
            "core_sha256": tree_digest(core),
            "engine": str(engine),
            "engine_sha256": tree_digest(engine),
            "input": str(source),
            "input_sha256": hashlib.sha256(b"{}").hexdigest(),
            "relay": str(relay),
            "node_sha256": hashlib.sha256(node.read_bytes()).hexdigest(),
            "script_sha256": hashlib.sha256(
                Path(browser_sandbox.__file__)
                .with_name("browser_driver.cjs")
                .read_bytes()
            ).hexdigest(),
        }
        command = sandbox_command(
            vars(WorkerLimits()), ["/usr/bin/node", "/argos-browser.cjs"]
        )
        mounted, descriptor = browser_command(command.copy(), settings)
        import os

        try:
            assert os.read(descriptor, 10) == b"{}"
        finally:
            os.close(descriptor)
        assert "--unshare-all" in mounted
        assert "--share-net" not in mounted
        assert str(core) in mounted and "/argos-relay.sock" in mounted
        assert str(tmp_path) not in mounted
        source.chmod(0o644)
        with pytest.raises(RuntimeError, match="private browser input"):
            browser_command(command.copy(), settings)
        with pytest.raises(RuntimeError, match="entry point"):
            browser_command(
                sandbox_command(vars(WorkerLimits()), ["/usr/bin/true"]), settings
            )
        (core / "modified").write_text("changed")
        with pytest.raises(RuntimeError, match="identity changed"):
            browser_command(command.copy(), settings)
        node.write_bytes(b"different Node binary")
        with pytest.raises(RuntimeError, match="Node identity changed"):
            browser_command(command.copy(), settings)


def observation(**updates):
    return json.dumps(
        dict(
            version=VERSION,
            state="observed",
            links=["https://fixture.test/dynamic?secret=value"],
            limited=False,
            blocked_websockets=0,
            browser_version="test",
            **updates,
        )
    ).encode()


def test_dom_links_remain_private_candidates_and_summary_is_redacted():
    value = decode_observation(observation(), (), {"browser_version": "test"}, False)
    assert value.links == ("https://fixture.test/dynamic?secret=value",)
    assert "secret" not in repr(value)
    assert "secret" not in json.dumps(value.summary())


@pytest.mark.parametrize(
    "changes",
    [
        {"state": "confirmed"},
        {"limited": 1},
        {"blocked_websockets": -1},
        {"browser_version": "unqualified"},
        {"links": ["x" * 8193]},
        {"unexpected": 1},
    ],
)
def test_malformed_observation_fails_closed(changes):
    value = json.loads(observation())
    value.update(changes)
    with pytest.raises(IsolationError, match="observation"):
        decode_observation(
            json.dumps(value).encode(), (), {"browser_version": "test"}, False
        )


def test_browser_task_ceiling_remains_bounded():
    assert WorkerLimits(tasks=256).tasks == 256
    with pytest.raises(ValueError, match="tasks"):
        WorkerLimits(tasks=257)
    with pytest.raises(ValueError, match="file_descriptors"):
        WorkerLimits(file_descriptors=1025)


def test_private_proof_error_is_not_downgraded_to_a_blocked_resource(relay, tmp_path):
    from argos.backend.attack.web.receipts import WebIntegrityError

    relay.mediator.side_effect = WebIntegrityError("injected proof mismatch")
    with pytest.raises(WebIntegrityError):
        relay.answer(request())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(relay.listener.getsockname())
        client.sendall(json.dumps(request()).encode() + b"\n")
        with pytest.raises(WebIntegrityError):
            relay.poll()

    # The trusted child activity callback also sees a full IPC peer close,
    # while a normal request half-close remains usable (covered above).
    import threading
    import time

    started = Event()
    stopped = Event()
    address = str(tmp_path / "closed")
    second = BrowserRelay(
        address, "https://fixture.test/", lambda _: exchange(), lambda: True, None
    )

    def mediate(_):
        started.set()
        until = time.monotonic() + 2
        while second.alive() and time.monotonic() < until:
            time.sleep(0.01)
        assert not second.alive(), "Closed IPC peer left its HTTP child active"
        stopped.set()
        return exchange()

    second.mediator = mediate

    def peer_client():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.connect(address)
            stream.sendall(json.dumps(request()).encode() + b"\n")
            stream.shutdown(socket.SHUT_WR)
            assert started.wait(2)

    thread = threading.Thread(target=peer_client)
    try:
        thread.start()
        until = time.monotonic() + 2
        while not stopped.is_set() and time.monotonic() < until:
            second.poll()
            time.sleep(0.01)
        assert stopped.is_set()
    finally:
        second.close()
        thread.join(timeout=3)
