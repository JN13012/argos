"""Internal offline browser primitive; not a mission execution capability.

All HTTP bytes must come from a trusted, bounded mediator. This module never
opens an Internet socket. Durable policy/tickets and CLI integration are W4.2.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Event

from argos.backend.core.browser_sandbox import tree_digest
from argos.backend.core.isolated_worker import (
    IsolationError,
    OfflineWorker,
    WorkerLimits,
)

from .config import _normalize_url, _origin
from .transport import HTTPExchange

VERSION = "argos-browser-v1"
PLAYWRIGHT_VERSION = "1.65.1"
CHROMIUM_REVISION = "1255"
_CORE = Path(__file__).resolve().parents[2] / "core"
_RESOURCES = {
    "document",
    "stylesheet",
    "image",
    "media",
    "font",
    "script",
    "texttrack",
    "xhr",
    "fetch",
    "eventsource",
    "manifest",
    "other",
}


@dataclass(frozen=True)
class BrowserRequest:
    url: str = field(repr=False)
    method: str
    resource: str


@dataclass(frozen=True)
class BrowserInstallation:
    """Administrator paths only. Never accepted from a page or agent."""

    core: Path
    engine: Path

    def identity(self) -> dict:
        try:
            if not self.core.is_absolute() or not self.engine.is_absolute():
                raise ValueError
            package = json.loads((self.core / "package.json").read_text())
            manifest = json.loads((self.core / "browsers.json").read_text())
            browser = next(
                b
                for b in manifest["browsers"]
                if b["name"] == "chromium-headless-shell"
            )
            if (
                package["name"] != "playwright-core"
                or package["version"] != PLAYWRIGHT_VERSION
                or browser["revision"] != CHROMIUM_REVISION
                or not (self.engine / "chrome-headless-shell").is_file()
                or not Path("/usr/bin/node").is_file()
            ):
                raise ValueError
            return {
                "core": str(self.core),
                "engine": str(self.engine),
                "core_sha256": tree_digest(self.core),
                "engine_sha256": tree_digest(self.engine),
                "playwright_version": PLAYWRIGHT_VERSION,
                "chromium_revision": CHROMIUM_REVISION,
                "browser_version": browser["browserVersion"],
                "node_sha256": hashlib.sha256(
                    Path("/usr/bin/node").read_bytes()
                ).hexdigest(),
            }
        except (OSError, ValueError, KeyError, StopIteration, RuntimeError):
            raise IsolationError(
                "Missing or unsupported browser installation"
            ) from None


class BrowserRelay:
    """Bounded single-flight Unix IPC, polled on the owning runtime thread.

    The mediator is trusted code, must honor active/cancel/deadlines itself,
    and must perform the full signed HTTP policy. It is never page-selected.
    No cookies, Authorization or page-supplied headers cross this interface.
    """

    def __init__(
        self,
        path: str,
        url: str,
        mediator: Callable[[BrowserRequest], HTTPExchange],
        active: Callable[[], bool],
        cancel: Event | None,
    ):
        self.origin = _origin(_normalize_url(url, private_profile=True))
        self.mediator = mediator
        self.active = active
        self.cancel = cancel
        self.events: list[dict] = []
        self.limited = False
        self.body_bytes = 0
        self.attempts = 0
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        os.chmod(path, 0o600)
        self.listener.listen(1)
        self.listener.setblocking(False)
        self.connection: socket.socket | None = None
        self.buffer = b""
        self.deadline = 0.0

    def alive(self) -> bool:
        return not (self.cancel and self.cancel.is_set()) and self.active()

    def answer(self, payload: object) -> dict:
        self.attempts += 1
        if self.attempts > 64 or not self.alive():
            self.limited = True
            return {"blocked": True}
        try:
            if not isinstance(payload, dict) or set(payload) != {
                "url",
                "method",
                "resource",
            }:
                raise ValueError
            raw, method, resource = (
                payload["url"],
                payload["method"],
                payload["resource"],
            )
            if not isinstance(raw, str) or len(raw.encode()) > 8192:
                raise ValueError
            url = _normalize_url(raw, private_profile=True)
            allowed = (
                method in ("GET", "HEAD")
                and resource in _RESOURCES
                and _origin(url) == self.origin
            )
            event = {
                "url_sha256": hashlib.sha256(url.encode()).hexdigest(),
                "method": method if method in ("GET", "HEAD") else "other",
                "resource": resource if resource in _RESOURCES else "other",
                "state": "blocked",
            }
            self.events.append(event)
            if not allowed:
                self.limited = True
                return {"blocked": True}
            response = self.mediator(BrowserRequest(url, method, resource))
            # Never forward a partial, compressed or oversized body as a valid resource.
            if (
                not self.alive()
                or response.state != "completed"
                or not response.body_complete
                or response.error is not None
                or type(response.status) is not int
                or not 200 <= response.status <= 599
                or response.status in {301, 302, 303, 304, 305, 307, 308}
                or len(response.body) > 524288
                or self.body_bytes + len(response.body) > 8 * 1024 * 1024
                or len(response.headers) > 100
            ):
                self.limited = True
                return {"blocked": True}
            headers = []
            seen = set()
            for name, value in response.headers:
                key = name.lower()
                if not key or any(
                    c not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"
                    for c in key
                ):
                    raise ValueError
                if len(value.encode()) > 8192 or any(
                    ord(c) < 32 or ord(c) == 127 for c in value
                ):
                    raise ValueError
                if key in {
                    "set-cookie",
                    "connection",
                    "transfer-encoding",
                    "content-length",
                    "keep-alive",
                    "upgrade",
                    "proxy-authenticate",
                    "proxy-authorization",
                }:
                    continue
                if (
                    key in seen
                    or key == "content-encoding"
                    and value.lower() != "identity"
                ):
                    raise ValueError
                seen.add(key)
                headers.append([key, value])
            if sum(len(k.encode()) + len(v.encode()) for k, v in headers) > 32768:
                raise ValueError
            self.body_bytes += len(response.body)
            event["state"] = "supplied"
            return {
                "status": response.status,
                "headers": headers,
                "body": base64.b64encode(response.body).decode("ascii"),
            }
        except (ValueError, TypeError):
            self.limited = True
            return {"blocked": True}

    def poll(self) -> bool:
        if not self.alive():
            return False
        try:
            if self.connection is None:
                self.connection, _ = self.listener.accept()
                self.connection.setblocking(False)
                self.deadline = time.monotonic() + 2
                self.buffer = b""
            data = self.connection.recv(16385 - len(self.buffer))
            self.buffer += data
            if len(self.buffer) > 16384 or time.monotonic() > self.deadline:
                raise ValueError
            if b"\n" not in self.buffer:
                if not data:
                    raise ValueError
                return True
            payload = json.loads(self.buffer)
            result = self.answer(payload)
            self.connection.settimeout(0.2)
            self.connection.sendall(json.dumps(result).encode())
            self.connection.close()
            self.connection = None
        except BlockingIOError:
            if self.connection is not None and time.monotonic() > self.deadline:
                self.connection.close()
                self.connection = None
                self.limited = True
        except (OSError, ValueError):
            self.limited = True
            if self.connection is not None:
                self.connection.close()
                self.connection = None
        return self.alive()

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
        self.listener.close()


@dataclass(frozen=True)
class BrowserObservation:
    state: str
    links: tuple[str, ...] = field(repr=False)
    events: tuple[dict, ...]
    limited: bool
    blocked_websockets: int
    profile: dict = field(repr=False)

    def summary(self) -> dict:
        return {
            "version": VERSION,
            "state": self.state,
            "links": len(self.links),
            "requests": list(self.events),
            "limited": self.limited,
            "blocked_websockets": self.blocked_websockets,
        }


class BrowserWorker:
    def __init__(self, installation: BrowserInstallation):
        self.installation = installation
        self.limits = WorkerLimits(
            memory_bytes=1024**3,
            tasks=256,
            wall_seconds=30,
            scratch_bytes=64 * 1024**2,
            output_bytes=524288,
            file_descriptors=1024,
        )

    def profile(self) -> dict:
        return {
            "version": VERSION,
            "limits": asdict(self.limits),
            **self.installation.identity(),
            "script_sha256": hashlib.sha256(
                (_CORE / "browser_driver.cjs").read_bytes()
            ).hexdigest(),
            "runtime_sha256": hashlib.sha256(
                b"".join(
                    (_CORE / name).read_bytes()
                    for name in (
                        "isolated_worker.py",
                        "worker_guardian.py",
                        "browser_sandbox.py",
                    )
                )
                + Path(__file__).read_bytes()
            ).hexdigest(),
        }

    def navigate(
        self,
        url: str,
        *,
        mediator: Callable[[BrowserRequest], HTTPExchange],
        active: Callable[[], bool],
        cancel: Event | None = None,
        expected_profile: dict | None = None,
    ) -> BrowserObservation:
        if not active() or cancel is not None and cancel.is_set():
            return BrowserObservation("cancelled", (), (), True, 0, {})
        url = _normalize_url(url, private_profile=True)
        if len(url.encode()) > 8192:
            raise ValueError("Browser URL limit")
        profile = self.profile()
        if expected_profile is not None and profile != expected_profile:
            raise IsolationError("Browser isolation profile changed")
        with tempfile.TemporaryDirectory(prefix="argos-browser-") as directory:
            path = Path(directory)
            payload = json.dumps({"url": url, "max_requests": 64}).encode()
            source = path / "input.json"
            source.touch(mode=0o600)
            source.write_bytes(payload)
            relay = BrowserRelay(str(path / "relay"), url, mediator, active, cancel)
            try:
                settings = {
                    **profile,
                    "relay": str(path / "relay"),
                    "input": str(source),
                    "input_sha256": hashlib.sha256(payload).hexdigest(),
                }
                if not relay.alive():
                    return BrowserObservation("cancelled", (), (), True, 0, profile)
                result = OfflineWorker(self.limits)._run(
                    ("/usr/bin/node", "/argos-browser.cjs"),
                    active=relay.poll,
                    cancel=cancel,
                    browser=settings,
                )
                if not relay.alive() or result.state == "cancelled":
                    return BrowserObservation(
                        "cancelled", (), tuple(relay.events), True, 0, profile
                    )
                if result.state == "timed_out":
                    return BrowserObservation(
                        "timed_out", (), tuple(relay.events), True, 0, profile
                    )
                if result.state != "completed":
                    raise IsolationError("Browser isolation or execution failed")
                observation = decode_observation(
                    result.stdout, tuple(relay.events), profile, relay.limited
                )
                # Detect installation changes while running; no fallback/replay.
                if self.profile() != profile:
                    raise IsolationError("Browser isolation profile changed")
                return observation
            finally:
                relay.close()


def decode_observation(
    data: bytes, events: tuple[dict, ...], profile: dict, limited: bool
) -> BrowserObservation:
    try:
        if len(data) > 524288:
            raise ValueError
        value = json.loads(data)
        if (
            set(value)
            != {
                "version",
                "state",
                "links",
                "limited",
                "blocked_websockets",
                "browser_version",
            }
            or value["browser_version"] != profile["browser_version"]
            or value["version"] != VERSION
            or value["state"] not in {"observed", "partial"}
            or type(value["limited"]) is not bool
            or type(value["blocked_websockets"]) is not int
            or not 0 <= value["blocked_websockets"] <= 2**31 - 1
            or not isinstance(value["links"], list)
            or len(value["links"]) > 128
        ):
            raise ValueError
        links = []
        for link in value["links"]:
            if not isinstance(link, str) or len(link.encode()) > 8192:
                raise ValueError
            # DOM links are candidates only, never permission to fetch them.
            try:
                links.append(
                    _normalize_url(link.split("#", 1)[0], private_profile=True)
                )
            except ValueError:
                limited = True
        limited = limited or value["limited"] or bool(value["blocked_websockets"])
        return BrowserObservation(
            "partial" if limited else value["state"],
            tuple(dict.fromkeys(links)),
            events,
            limited,
            value["blocked_websockets"],
            profile,
        )
    except (ValueError, TypeError, KeyError):
        raise IsolationError("Invalid browser observation") from None
