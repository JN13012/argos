"""Allowlisted HTTP receipts. Raw response headers/body never enter this payload."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from .contracts import WebRequest

if TYPE_CHECKING:
    from .transport import HTTPExchange

FINAL_STATES = frozenset({"completed", "partial", "failed", "cancelled", "interrupted"})
ERRORS = frozenset(
    {
        "mission_inactive",
        "approval_invalid",
        "scope_denied",
        "effect_denied",
        "dns_failed",
        "dns_denied",
        "dns_timeout",
        "tls_failed",
        "connect_failed",
        "protocol_failed",
        "request_timeout",
        "response_limit",
        "budget_exhausted",
        "cancelled",
        "interrupted",
        "isolation_unavailable",
        "evidence_failed",
        "unsupported_encoding",
        "profile_changed",
    }
)


class WebIntegrityError(ValueError):
    """A saved request, profile, receipt or event binding differs."""


class WebPersistenceError(RuntimeError):
    """Stop all new admissions after a storage failure."""


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def request_data(request: WebRequest) -> dict:
    value = {
        key: str(value) if isinstance(value, UUID) else value
        for key, value in asdict(request).items()
    }
    from .interaction import StructuredWebRequest

    if isinstance(request, StructuredWebRequest):
        value["request_version"] = 2
    return value


def load_request(data: str) -> WebRequest:
    value = json.loads(data)
    for key in ("mission_id", "request_id", "parent_request_id"):
        if value[key] is not None:
            value[key] = UUID(value[key])
    from .interaction import StructuredWebRequest

    if "request_version" in value:
        version = value.pop("request_version")
        if type(version) is not int or version != 2:
            raise ValueError("Unsupported request version")
        return StructuredWebRequest(**value)
    return WebRequest(**value)


@dataclass(frozen=True)
class WebJobSnapshot:
    id: UUID
    mission_id: UUID
    state: str
    error: str | None
    evidence_sha256: str | None


@dataclass(frozen=True)
class WebChainResult:
    exchanges: tuple[WebJobSnapshot, ...]
    stop_reason: str


def receipt(
    request: WebRequest,
    configuration_sha256: str,
    *,
    state: str,
    error: str | None,
    exchange: HTTPExchange | None = None,
    profile: dict | None = None,
    resolution: dict | None = None,
    dispatched: bool = False,
) -> dict:
    if state not in FINAL_STATES or error is not None and error not in ERRORS:
        raise ValueError("Invalid HTTP terminal outcome")
    if state == "completed" and (
        error is not None or exchange is None or exchange.state != "completed"
    ):
        raise ValueError("A completed outcome requires a complete exchange")
    # Header names are only compared; even a malicious header name is not exported.
    names = [name.lower() for name, _ in exchange.headers] if exchange else []
    value = {
        "version": "web-redaction-v1",
        "id": str(uuid4()),
        "request_id": str(request.request_id),
        "mission_id": str(request.mission_id),
        "request_sha256": digest(request_data(request)),
        "configuration_sha256": configuration_sha256,
        "profile_sha256": digest(profile),
        "resolution_sha256": digest(resolution),
        "state": state,
        "error": error,
        "dispatch": "possible" if dispatched else "not_started",
        "recorded_at": datetime.now(UTC).isoformat(),
        "response": None
        if exchange is None
        else {
            "status": exchange.status,
            "body_complete": exchange.body_complete,
            "retained_bytes": len(exchange.body),
            "has_location": "location" in names,
            "set_cookie_count": names.count("set-cookie"),
            "authentication_challenge": "www-authenticate" in names,
        },
        "coverage": {
            "capability": request.capability,
            "identity": "anonymous",
            "state": "executed" if state == "completed" else "blocked",
            "applicable": True if state == "completed" else None,
            "reason": "http_response" if state == "completed" else error or state,
        },
    }

    if state == "completed" and exchange is not None:
        from argos.backend.attack.recon.fingerprint_signals import http_indicators

        value["response"]["technology"] = http_indicators(
            exchange.headers,
            exchange.body,
            complete=exchange.body_complete,
            tls=exchange.tls,
        )
    if exchange is not None and exchange.tls is not None:
        value["response"]["tls"] = exchange.tls

    from .interaction import StructuredWebRequest, request_summary

    if isinstance(request, StructuredWebRequest):
        value["version"] = "web-redaction-v2"
        value["structured_request"] = request_summary(request)
    return value
