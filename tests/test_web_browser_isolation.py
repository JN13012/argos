"""Opt-in real Chromium qualification. Only in-memory owned page responses."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from argos.backend.attack.web.browser import BrowserInstallation, BrowserWorker
from argos.backend.attack.web.transport import HTTPExchange

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_BROWSER") != "1",
    reason="Requires Linux user systemd/bwrap and explicit browser installation paths",
)


@pytest.fixture
def browser():
    return BrowserWorker(
        BrowserInstallation(
            Path(os.environ["ARGOS_BROWSER_CORE"]),
            Path(os.environ["ARGOS_BROWSER_ENGINE"]),
        )
    )


def response(body, media="text/html", headers=()):
    return HTTPExchange(
        "completed", None, 200, (("content-type", media), *headers), body.encode(), True
    )


def test_real_browser_executes_js_loads_script_and_observes_api(browser):
    requests = []

    def mediator(req):
        requests.append(req)
        if req.url == "https://fixture.test/":
            return response('<!doctype html><body><script src="/app.js"></script>')
        if req.url.endswith("/app.js"):
            return response(
                "fetch('/api/data').then(r=>r.json()).then(v=>{"
                "document.body.innerHTML='<a href=\"'+v.link+'\">dynamic</a>';"
                "console.log('private-console-canary'); });",
                "application/javascript",
            )
        assert req.url.endswith("/api/data")
        return response(
            '{"link":"/dynamic?token=private-query-canary"}',
            "application/json",
            (("set-cookie", "private-cookie-canary=x"),),
        )

    result = browser.navigate(
        "https://fixture.test/", mediator=mediator, active=lambda: True
    )
    assert result.state == "observed"
    assert result.links == ("https://fixture.test/dynamic?token=private-query-canary",)
    assert [r.resource for r in requests] == ["document", "script", "fetch"]
    assert all(e["state"] == "supplied" for e in result.events)
    assert "canary" not in json.dumps(result.summary())
    assert result.profile["limits"]["tasks"] == 256


def test_real_browser_blocks_egress_post_ws_service_worker_and_native_udp(browser):
    called = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        port = udp.getsockname()[1]

        def mediator(req):
            called.append(req)
            assert req.url == "https://fixture.test/"
            return response(f"""<!doctype html><body><a href="/kept">kept</a><script>
fetch('https://other.test/leak').catch(()=>{{}});
fetch('/write', {{method:'POST', body:'private-post-canary'}}).catch(()=>{{}});
new WebSocket('wss://fixture.test/socket');
navigator.serviceWorker.register('/sw.js').catch(()=>{{}});
navigator.sendBeacon('/beacon', 'private-beacon-canary');
const peer = new RTCPeerConnection({{iceServers:[{{urls:'stun:127.0.0.1:{port}'}}]}});
peer.createDataChannel('test'); peer.createOffer().then(o=>peer.setLocalDescription(o));
</script>""")

        result = browser.navigate(
            "https://fixture.test/", mediator=mediator, active=lambda: True
        )
        assert result.state == "partial"
        assert result.blocked_websockets == 1
        assert len(called) == 1
        assert sum(e["state"] == "blocked" for e in result.events) >= 2
        udp.settimeout(0.1)
        with pytest.raises(TimeoutError):
            udp.recvfrom(8192)
        assert "canary" not in json.dumps(result.summary())


def test_real_browser_does_not_share_storage_between_invocations(browser):
    def mediator(req):
        return response("""<!doctype html><body><script>
const old = localStorage.getItem('private') || document.cookie || 'fresh';
localStorage.setItem('private','persisted'); document.cookie='token=persisted';
document.body.innerHTML='<a href="/'+old+'">state</a>';
</script>""")

    first = browser.navigate(
        "https://fixture.test/", mediator=mediator, active=lambda: True
    )
    second = browser.navigate(
        "https://fixture.test/", mediator=mediator, active=lambda: True
    )
    assert first.links == second.links == ("https://fixture.test/fresh",)


@pytest.mark.parametrize("mode", ["cancel", "revoke"])
def test_real_browser_stops_infinite_js_on_cancel_or_revocation(browser, mode):
    cancel = threading.Event()
    revoked = threading.Event()
    timer = None
    trigger_at = []

    def trigger():
        trigger_at.append(time.monotonic())
        (cancel if mode == "cancel" else revoked).set()

    def mediator(req):
        nonlocal timer
        timer = threading.Timer(0.8, trigger)
        timer.start()
        return response("<!doctype html><body><script>while(true){}</script>")

    try:
        result = browser.navigate(
            "https://fixture.test/",
            mediator=mediator,
            active=lambda: not revoked.is_set(),
            cancel=cancel,
        )
        assert result.state == "cancelled"
        assert result.links == ()
        assert trigger_at and time.monotonic() - trigger_at[0] < 2
        assert len(result.events) == 1
    finally:
        if timer:
            timer.cancel()


def test_real_browser_bounds_dom_and_treats_redirect_as_unsupported(browser):
    result = browser.navigate(
        "https://fixture.test/",
        mediator=lambda req: response(
            "<!doctype html><body><script>for(let i=0;i<300;i++){"
            'document.body.insertAdjacentHTML("beforeend",'
            '`<a href="/page/${i}">link</a>`);}'
            "</script>"
        ),
        active=lambda: True,
    )
    assert result.limited and len(result.links) == 128
    calls = []

    def redirect(req):
        calls.append(req)
        return replace(
            response("", headers=(("location", "https://other.test/"),)), status=302
        )

    result = browser.navigate(
        "https://fixture.test/", mediator=redirect, active=lambda: True
    )
    assert result.state == "partial" and len(calls) == 1


def test_real_browser_wall_deadline_does_not_invent_observation(browser):
    browser.limits = replace(browser.limits, wall_seconds=4)
    result = browser.navigate(
        "https://fixture.test/",
        mediator=lambda req: response(
            "<!doctype html><body><script>while(true){}</script>"
        ),
        active=lambda: True,
    )
    assert result.state == "timed_out" and result.links == ()


def test_browser_descendants_stop_when_runtime_is_killed(tmp_path):
    token = uuid4()
    unit = f"argos-worker-{token.hex}.service"
    ready = tmp_path / "ready"
    source = f"""
from pathlib import Path
from uuid import UUID
from unittest.mock import patch
from argos.backend.attack.web.browser import BrowserWorker, BrowserInstallation
from argos.backend.attack.web.transport import HTTPExchange
def mediator(req):
    Path({str(ready)!r}).write_text('served')
    return HTTPExchange('completed',None,200,(('content-type','text/html'),),
        b'<!doctype html><body><script>while(true){{}}</script>',True)
worker=BrowserWorker(BrowserInstallation(Path({os.environ["ARGOS_BROWSER_CORE"]!r}),
    Path({os.environ["ARGOS_BROWSER_ENGINE"]!r})))
with patch('argos.backend.core.isolated_worker.uuid4',
           return_value=UUID({str(token)!r})):
    worker.navigate('https://fixture.test/',mediator=mediator,active=lambda:True)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", source],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 12
        while not ready.exists() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.02)
        assert ready.exists(), "Browser did not reach the fixture"
        status = subprocess.run(
            ["systemctl", "--user", "show", unit, "--property=ControlGroup", "--value"],
            capture_output=True,
            text=True,
            timeout=1,
            check=True,
        )
        group = Path("/sys/fs/cgroup") / status.stdout.strip().lstrip("/")
        assert len(group.joinpath("cgroup.procs").read_text().split()) > 3
        process.kill()
        process.wait(timeout=2)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if (
                not group.exists()
                or "populated 0" in group.joinpath("cgroup.events").read_text()
            ):
                break
            time.sleep(0.02)
        else:
            pytest.fail("Browser descendants survived runtime death")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)
        subprocess.run(
            ["systemctl", "--user", "stop", unit],
            capture_output=True,
            timeout=3,
            check=False,
        )
