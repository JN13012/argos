"""Immutable HTTP DTOs, without sockets, execution or authorization bypasses."""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import ClassVar
from uuid import UUID, uuid4

from .config import _keys, _text
from .execution_config import HTTP_CAPABILITIES


def _uuid(value: object) -> None:
    if not isinstance(value, UUID):
        raise ValueError("Expected a runtime-assigned UUID")


def _integer(value: object, maximum: int = 2**63 - 1) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Expected a bounded nonnegative integer")


def _instant(value: datetime) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("Expected a timezone-aware instant")


def _digest(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Expected a SHA-256 digest")


class WebErrorCode(StrEnum):
    MISSION_INACTIVE = "mission_inactive"
    APPROVAL_INVALID = "approval_invalid"
    SCOPE_DENIED = "scope_denied"
    EFFECT_DENIED = "effect_denied"
    DNS_FAILED = "dns_failed"
    DNS_DENIED = "dns_denied"
    DNS_TIMEOUT = "dns_timeout"
    TLS_FAILED = "tls_failed"
    CONNECT_FAILED = "connect_failed"
    PROTOCOL_FAILED = "protocol_failed"
    REQUEST_TIMEOUT = "request_timeout"
    RESPONSE_LIMIT = "response_limit"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    ISOLATION_UNAVAILABLE = "isolation_unavailable"
    EVIDENCE_FAILED = "evidence_failed"


@dataclass(frozen=True)
class WebRequest:
    ALLOWED_CAPABILITIES: ClassVar[frozenset[str]] = HTTP_CAPABILITIES
    ALLOWED_METHODS: ClassVar[frozenset[str]] = frozenset({"GET", "HEAD"})

    mission_id: UUID
    url: str = field(repr=False)
    capability: str = "http.discover"
    method: str = "GET"
    request_id: UUID = field(default_factory=uuid4)
    parent_request_id: UUID | None = None

    def __post_init__(self) -> None:
        _uuid(self.mission_id)
        _uuid(self.request_id)
        if self.parent_request_id is not None:
            _uuid(self.parent_request_id)
        _text(self.url)
        if len(self.url.encode()) > 8192:
            raise ValueError("Request URL exceeds the HTTP contract limit")
        if (
            not isinstance(self.capability, str)
            or not isinstance(self.method, str)
            or self.capability not in self.ALLOWED_CAPABILITIES
            or self.method not in self.ALLOWED_METHODS
        ):
            raise ValueError("Unsupported anonymous HTTP request")
        if self.capability == "http.check_redirect" and self.method != "GET":
            raise ValueError("Redirect checks require GET")

    @classmethod
    def from_agent(cls, mission_id: UUID, payload: object) -> "WebRequest":
        data = _keys(payload, {"url", "method", "capability"}, {"url"})
        return cls(mission_id, **data)


@dataclass(frozen=True)
class ResolvedWebTarget:
    """Trusted resolver output; never an agent request field or public grant."""

    hostname: str
    addresses: tuple[str, ...]
    observed_at: datetime

    def __post_init__(self) -> None:
        _text(self.hostname)
        _instant(self.observed_at)
        if (
            not isinstance(self.addresses, (tuple, list))
            or not 1 <= len(self.addresses) <= 16
        ):
            raise ValueError("Expected 1 to 16 resolved addresses")
        for value in self.addresses:
            if not isinstance(value, str) or str(ipaddress.ip_address(value)) != value:
                raise ValueError("Resolver output requires canonical numeric addresses")
        object.__setattr__(self, "addresses", tuple(self.addresses))


@dataclass(frozen=True)
class WebBudgetUsage:
    """Runtime snapshot, not a reservation or a durable counter."""

    mission_id: UUID
    requests_used: int = 0
    evidence_bytes_used: int = 0
    in_flight: int = 0
    elapsed_ms: int = 0

    def __post_init__(self) -> None:
        _uuid(self.mission_id)
        for value in (
            self.requests_used,
            self.evidence_bytes_used,
            self.in_flight,
            self.elapsed_ms,
        ):
            _integer(value)


@dataclass(frozen=True)
class WebBudgetDemand:
    requests: int
    evidence_bytes: int

    def __post_init__(self) -> None:
        if type(self.requests) is not int or self.requests != 1:
            raise ValueError("One demand represents one physical attempt")
        _integer(self.evidence_bytes)
        if not self.evidence_bytes:
            raise ValueError("Evidence capacity must be reserved")


@dataclass(frozen=True)
class WebResponse:
    """Private transport DTO; not a redacted report or an evidence receipt."""

    request_id: UUID
    status: int
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    connect_ip: str
    tls_hostname: str | None
    started_at: datetime
    finished_at: datetime
    elapsed_ms: int
    retained_bytes: int
    body_complete: bool
    evidence_id: UUID

    def __post_init__(self) -> None:
        _uuid(self.request_id)
        _uuid(self.evidence_id)
        _instant(self.started_at)
        _instant(self.finished_at)
        if (
            self.finished_at < self.started_at
            or type(self.status) is not int
            or not 200 <= self.status <= 599
        ):
            raise ValueError("Invalid final HTTP response")
        _integer(self.elapsed_ms)
        _integer(self.retained_bytes, 16777216)
        if type(self.body_complete) is not bool:
            raise ValueError("Response completeness must be explicit")
        if not isinstance(self.headers, (tuple, list)) or len(self.headers) > 100:
            raise ValueError("Too many response headers")
        headers = []
        size = 0
        for pair in self.headers:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValueError("Expected ordered header pairs")
            name, value = pair
            if not isinstance(name, str) or not re.fullmatch(
                r"[!#$%&'*+.^_`|~0-9a-zA-Z-]+", name
            ):
                raise ValueError("Invalid HTTP header name")
            if not isinstance(value, str) or any(c in value for c in "\r\n\x00"):
                raise ValueError("Invalid HTTP header value")
            length = len(name.encode()) + len(value.encode()) + 4
            if length > 8192:
                raise ValueError("Response header line exceeds limit")
            size += length
            headers.append((name, value))
        if size > 32768:
            raise ValueError("Response headers exceed limit")
        object.__setattr__(self, "headers", tuple(headers))
        if str(ipaddress.ip_address(self.connect_ip)) != self.connect_ip:
            raise ValueError("Expected a canonical connection address")
        if self.tls_hostname is not None:
            _text(self.tls_hostname)


@dataclass(frozen=True)
class WebFailure:
    request_id: UUID
    code: WebErrorCode
    phase: str
    request_sent: bool = False
    retained_bytes: int = 0
    evidence_id: UUID | None = None

    def __post_init__(self) -> None:
        _uuid(self.request_id)
        if (
            type(self.code) is not WebErrorCode
            or not isinstance(self.phase, str)
            or self.phase
            not in {
                "policy",
                "budget",
                "dns",
                "connect",
                "tls",
                "read",
                "evidence",
                "recovery",
            }
        ):
            raise ValueError("Expected stable HTTP failure code and phase")
        if type(self.request_sent) is not bool:
            raise ValueError("Request dispatch status must be explicit")
        _integer(self.retained_bytes, 16777216)
        if self.evidence_id is not None:
            _uuid(self.evidence_id)


@dataclass(frozen=True)
class WebEvidence:
    """Receipt contract; storage/redaction and integrity verification are W2.3."""

    id: UUID
    mission_id: UUID
    request_id: UUID
    configuration_sha256: str
    profile_sha256: str
    payload_sha256: str
    redaction_version: str = "web-redaction-v1"

    def __post_init__(self) -> None:
        for value in (self.id, self.mission_id, self.request_id):
            _uuid(value)
        for value in (
            self.configuration_sha256,
            self.profile_sha256,
            self.payload_sha256,
        ):
            _digest(value)
        if self.redaction_version != "web-redaction-v1":
            raise ValueError("Unsupported evidence redaction version")


class CoverageState(StrEnum):
    PLANNED = "planned"
    EXECUTED = "executed"
    VERIFIED = "verified"
    BLOCKED = "blocked"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class WebCoverage:
    capability: str
    route_id: UUID
    state: CoverageState
    applicable: bool | None
    reason: str
    evidence_ids: tuple[UUID, ...] = ()
    identity: str = "anonymous"

    def __post_init__(self) -> None:
        _uuid(self.route_id)
        if (
            not isinstance(self.capability, str)
            or self.capability not in HTTP_CAPABILITIES | {"http.interact"}
            or type(self.state) is not CoverageState
            or self.identity != "anonymous"
        ):
            raise ValueError("Unsupported coverage contract")
        if self.applicable is not None and type(self.applicable) is not bool:
            raise ValueError("Applicability must be explicit or unknown")
        if not isinstance(self.reason, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]{0,63}", self.reason
        ):
            raise ValueError("Use a stable coverage reason code")
        if (
            not isinstance(self.evidence_ids, (list, tuple))
            or len(self.evidence_ids) > 256
        ):
            raise ValueError("Expected bounded evidence references")
        for value in self.evidence_ids:
            _uuid(value)
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if self.state is CoverageState.NOT_APPLICABLE:
            if self.applicable is not False:
                raise ValueError("Non-applicable coverage needs a justification")
        elif self.applicable is False:
            raise ValueError("Unavailable coverage is not non-applicable")
        if self.state in {CoverageState.EXECUTED, CoverageState.VERIFIED} and (
            self.applicable is not True or not self.evidence_ids
        ):
            raise ValueError("Executed coverage requires applicability and evidence")
