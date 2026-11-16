"""Internal isolated HTTP primitive, called by the ticket-owning runtime.

Only the trusted ticket-owning runtime may call this with a freshly revalidated
plan. A Python plan is not an execution grant. No host transport fallback.
"""

from __future__ import annotations

import hashlib
import json
import struct
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event
from urllib.parse import quote, urlsplit

from argos.backend.core.isolated_worker import IsolationError, OfflineWorker
from argos.backend.core.network_policy import NetworkPolicy
from argos.backend.core.network_worker import NetworkTools

from .policy import PreparedWebRequest
from .receipts import digest, request_data

_CORE = Path(__file__).resolve().parents[2] / "core"
_CA = "/etc/ssl/certs/ca-certificates.crt"
_ARGUMENTS = ("/usr/bin/python3", "-I", "/argos-http.py")


@dataclass(frozen=True)
class HTTPExchange:
    """Private bounded transport bytes, never an exported finding or proof."""

    state: str
    error: str | None
    status: int | None
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_complete: bool


def decode_frame(data: bytes, body_limit: int) -> HTTPExchange:
    try:
        if len(data) < 4:
            raise ValueError
        length = struct.unpack("!I", data[:4])[0]
        if not 1 <= length <= 65536 or len(data) < 4 + length:
            raise ValueError
        metadata = json.loads(data[4 : 4 + length])
        if set(metadata) != {
            "status",
            "headers",
            "error",
            "body_complete",
            "body_bytes",
            "body_sha256",
        }:
            raise ValueError
        body = data[4 + length :]
        if (
            type(metadata["body_bytes"]) is not int
            or len(body) != metadata["body_bytes"]
            or len(body) > body_limit
        ):
            raise ValueError
        if hashlib.sha256(body).hexdigest() != metadata["body_sha256"]:
            raise ValueError
        status = metadata["status"]
        if status is not None and (type(status) is not int or not 200 <= status <= 599):
            raise ValueError
        error = metadata["error"]
        if error not in (
            None,
            "connect_failed",
            "tls_failed",
            "protocol_failed",
            "request_timeout",
            "response_limit",
            "unsupported_encoding",
        ):
            raise ValueError
        if (
            type(metadata["body_complete"]) is not bool
            or metadata["body_complete"]
            and error is not None
        ):
            raise ValueError
        fields = metadata["headers"]
        if not isinstance(fields, list) or len(fields) > 100:
            raise ValueError
        if any(
            not isinstance(pair, list)
            or len(pair) != 2
            or any(
                not isinstance(value, str) or any(c in value for c in "\r\n\x00")
                for value in pair
            )
            for pair in fields
        ):
            raise ValueError
        if error is None and (status is None or not metadata["body_complete"]):
            raise ValueError
        return HTTPExchange(
            "completed" if error is None else "partial" if status else "failed",
            error,
            status,
            tuple(tuple(pair) for pair in fields),
            body,
            metadata["body_complete"],
        )
    except (ValueError, TypeError, KeyError, struct.error):
        raise IsolationError("Invalid HTTP worker frame") from None


class HTTPWorker:
    def __init__(self, tools: NetworkTools | None = None, *, ca_bundle: str = _CA):
        self.tools = tools or NetworkTools()
        # Administrator configuration only; no value comes from WebRequest.
        ca = Path(ca_bundle)
        if not ca.is_absolute() or not ca.is_file():
            raise IsolationError("Missing administrator CA bundle")
        self.ca = ca.resolve()

    def profile(self, plan: PreparedWebRequest) -> dict:
        policy = NetworkPolicy(plan.target_ip, (plan.preflight.port,))
        return {
            "version": "argos-http-worker-v1",
            "configuration_sha256": plan.preflight.configuration_sha256,
            "request_id": str(plan.preflight.request.request_id),
            "request_sha256": digest(request_data(plan.preflight.request)),
            "timeout_ms": plan.preflight.timeout_ms,
            "host_header": plan.host_header,
            "tls_hostname": plan.tls_hostname,
            "target_ip": policy.target_ip,
            "connect_ip": policy.connect_ip,
            "port": plan.preflight.port,
            "limits": asdict(plan.preflight.worker_limits),
            "body_bytes": plan.preflight.effective_body_bytes,
            "tools": self.tools.identity(),
            "ca_sha256": hashlib.sha256(self.ca.read_bytes()).hexdigest(),
            "script_sha256": hashlib.sha256(
                (_CORE / "http_transport.py").read_bytes()
            ).hexdigest(),
            "runtime_sha256": hashlib.sha256(
                b"".join(
                    (_CORE / name).read_bytes()
                    for name in (
                        "isolated_worker.py",
                        "worker_guardian.py",
                        "network_guardian.py",
                        "http_sandbox.py",
                        "network_policy.py",
                        "network_anchor.py",
                    )
                )
                + Path(__file__).read_bytes()
            ).hexdigest(),
            "rules_sha256": hashlib.sha256(policy.nft_rules().encode()).hexdigest(),
        }

    def exchange(
        self,
        plan: PreparedWebRequest,
        *,
        active: Callable[[], bool],
        cancel: Event | None = None,
        expected_profile: dict | None = None,
    ) -> HTTPExchange:
        if not active() or cancel is not None and cancel.is_set():
            return HTTPExchange("cancelled", "cancelled", None, (), b"", False)
        policy = NetworkPolicy(plan.target_ip, (plan.preflight.port,))
        profile = self.profile(plan)
        if expected_profile is not None and profile != expected_profile:
            raise IsolationError("HTTP isolation profile changed")
        parts = urlsplit(plan.preflight.request.url)
        settings = {
            "connect_ip": policy.connect_ip,
            "port": plan.preflight.port,
            "host_header": plan.host_header,
            "tls_hostname": plan.tls_hostname,
            "method": plan.preflight.request.method,
            "request_target": parts.path
            + (
                "?" + quote(parts.query, safe="!$&'()*+,-./:;=?@_~%")
                if parts.query
                else ""
            ),
            "timeout_ms": plan.preflight.timeout_ms,
            "body_bytes": plan.preflight.effective_body_bytes,
            **{
                key: getattr(plan.preflight.execution_limits, key)
                for key in (
                    "response_header_bytes",
                    "response_header_count",
                    "header_line_bytes",
                )
            },
        }
        payload = json.dumps(settings, ensure_ascii=True).encode()
        if len(payload) > 65536:
            raise IsolationError("HTTP worker input limit")
        with tempfile.NamedTemporaryFile(prefix="argos-http-") as source:
            source.write(payload)
            source.flush()
            network = {
                "target_ip": policy.target_ip,
                "ports": list(policy.ports),
                "tools": profile["tools"],
                "http": {
                    "input": source.name,
                    "input_sha256": hashlib.sha256(payload).hexdigest(),
                    "ca": str(self.ca),
                    "ca_sha256": profile["ca_sha256"],
                    "script_sha256": profile["script_sha256"],
                },
            }
            result = OfflineWorker(plan.preflight.worker_limits)._run(
                _ARGUMENTS, cancel=cancel, active=active, network=network
            )
        if (
            not active()
            or cancel is not None
            and cancel.is_set()
            or result.state == "cancelled"
        ):
            return HTTPExchange("cancelled", "cancelled", None, (), b"", False)
        if result.state != "completed":
            return HTTPExchange(
                "failed",
                "request_timeout"
                if result.state == "timed_out"
                else "isolation_unavailable",
                None,
                (),
                b"",
                False,
            )
        return decode_frame(result.stdout, plan.preflight.effective_body_bytes)
