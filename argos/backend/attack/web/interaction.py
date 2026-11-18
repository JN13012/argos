"""Explicit v4 grants and bounded, anonymous structured HTTP requests."""

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from typing import ClassVar

from .browser_config import WebBrowserConfig
from .config import _keys, _strings
from .contracts import WebRequest, _integer

INTERACTION_CAPABILITY = "http.interact"
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
METHODS = READ_METHODS | {"POST", "PUT", "PATCH", "DELETE"}
HEADER_NAMES = frozenset({"accept", "content-type"})
MEDIA_TYPES = frozenset(
    {"application/json", "application/x-www-form-urlencoded", "text/plain"}
)


@dataclass(frozen=True)
class InteractionLimits:
    methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    body_bytes: int = 16384
    header_bytes: int = 2048

    def __post_init__(self) -> None:
        methods = _strings(self.methods, nonempty=True)
        if len(methods) != len(set(methods)) or not set(methods) <= METHODS:
            raise ValueError("Unsupported interaction methods")
        object.__setattr__(self, "methods", tuple(sorted(methods)))
        _integer(self.body_bytes, 16384)
        _integer(self.header_bytes, 2048)


@dataclass(frozen=True)
class WebInteractionConfig(WebBrowserConfig):
    VERSION: ClassVar[int] = 4
    ALLOWED_CAPABILITIES: ClassVar[frozenset[str]] = (
        WebBrowserConfig.ALLOWED_CAPABILITIES | {INTERACTION_CAPABILITY}
    )
    schema_version: int = 4
    capabilities: tuple[str, ...] = (
        "browser.discover",
        "http.discover",
        INTERACTION_CAPABILITY,
    )
    interaction: InteractionLimits = field(default_factory=InteractionLimits)

    def __post_init__(self) -> None:
        if not isinstance(self.interaction, InteractionLimits):
            raise ValueError("Typed interaction limits required")
        super().__post_init__()
        if INTERACTION_CAPABILITY not in self.capabilities:
            raise ValueError("Interaction capability required")

    @classmethod
    def from_dict(cls, value: object) -> "WebInteractionConfig":
        from .browser_config import WebBrowserLimits

        fields = cls._fields(value, browser=True, interaction=True)
        assert isinstance(value, dict)
        return cls(
            **fields,
            browser=WebBrowserLimits(
                **_keys(value["browser"], set(WebBrowserLimits.__dataclass_fields__))
            ),
            interaction=InteractionLimits(
                **_keys(value["interaction"], {"methods", "body_bytes", "header_bytes"})
            ),
        )


@dataclass(frozen=True)
class StructuredWebRequest(WebRequest):
    """Private UTF-8 input, never printed in repr or receipts."""

    ALLOWED_CAPABILITIES: ClassVar[frozenset[str]] = frozenset({INTERACTION_CAPABILITY})
    ALLOWED_METHODS: ClassVar[frozenset[str]] = METHODS
    capability: str = INTERACTION_CAPABILITY
    method: str = "POST"
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.body, str):
            raise ValueError("UTF-8 request text required")
        try:
            if len(self.body.encode("utf-8")) > 16384:
                raise ValueError("Request body exceeds contract")
        except UnicodeError:
            raise ValueError("Invalid UTF-8 request text") from None
        if self.method in READ_METHODS and self.body:
            raise ValueError("Read methods cannot carry a body")
        if not isinstance(self.headers, (tuple, list)) or len(self.headers) > 2:
            raise ValueError("Bounded header pairs required")
        headers = []
        seen = set()
        for pair in self.headers:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValueError("Invalid header pair")
            name, value = pair
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or name.lower() not in HEADER_NAMES
                or name.lower() in seen
                or any(not 32 <= ord(c) < 127 for c in value)
            ):
                raise ValueError("Unsupported request header")
            name = name.lower()
            if name == "content-type" and value.lower() not in MEDIA_TYPES | {
                v + "; charset=utf-8" for v in MEDIA_TYPES
            }:
                raise ValueError("Unsupported request media type")
            seen.add(name)
            headers.append((name, value))
        if self.body and "content-type" not in seen:
            raise ValueError("A body requires its explicit content type")
        if sum(len(k) + len(v) for k, v in headers) > 2048:
            raise ValueError("Request headers exceed contract")
        object.__setattr__(self, "headers", tuple(sorted(headers)))

    @classmethod
    def from_agent(cls, mission_id, payload: object) -> "StructuredWebRequest":
        data = _keys(payload, {"url", "method", "headers", "body"}, {"url", "method"})
        headers = data.pop("headers", {})
        if not isinstance(headers, dict):
            raise ValueError("Header mapping required")
        return cls(mission_id, **data, headers=tuple(headers.items()))


def request_summary(request: StructuredWebRequest) -> dict:
    from .receipts import digest

    return dict(
        version=1,
        method=request.method,
        body_bytes=len(request.body.encode()),
        body_sha256=hashlib.sha256(request.body.encode()).hexdigest(),
        headers_sha256=digest(request.headers),
        header_count=len(request.headers),
    )


def request_view(store, request_id) -> dict:
    request, _ = store.private_request(request_id)
    if not isinstance(request, StructuredWebRequest):
        raise ValueError("Structured request required")
    snapshot = store.snapshot(request_id)
    proof = store.evidence(request_id)
    return dict(
        request_id=str(snapshot.id),
        mission_id=str(snapshot.mission_id),
        state=snapshot.state,
        error=snapshot.error,
        evidence_sha256=snapshot.evidence_sha256,
        structured_request=request_summary(request),
        response=proof["response"] if proof else None,
        dispatch=proof["dispatch"]
        if proof
        else "not_started"
        if snapshot.state == "pending"
        else "possible",
        security_testing="not_tested",
    )


def private_request_file(path) -> dict:
    """Read client request content once, bounded, without following symlinks."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > 196608
        ):
            raise ValueError("Private bounded request file required")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(196609)
        if len(raw) > 196608:
            raise ValueError("Request file exceeds limit")
    finally:
        os.close(descriptor)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate request key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Request object required")
    return value
