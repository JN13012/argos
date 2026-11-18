"""Bounded response preparation and private, single-consumer memory handoff."""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from uuid import UUID

from .receipts import WebIntegrityError, digest
from .transport import HTTPExchange


def relay_response(
    response: HTTPExchange, maximum: int, *, allow_redirects: bool = False
) -> HTTPExchange | None:
    if (
        response.state != "completed"
        or not response.body_complete
        or response.error is not None
        or type(response.status) is not int
        or not 200 <= response.status <= 599
        or response.status in {304, 305}
        or not allow_redirects
        and response.status in {301, 302, 303, 307, 308}
        or len(response.body) > maximum
        or len(response.headers) > 100
    ):
        return None
    headers = []
    seen = set()
    for name, value in response.headers:
        key = name.lower()
        if (
            not key
            or any(
                c not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"
                for c in key
            )
            or len(value.encode()) > 8192
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            return None
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
        if key in seen or key == "content-encoding" and value.lower() != "identity":
            return None
        seen.add(key)
        headers.append((key, value))
    if sum(len(k.encode()) + len(v.encode()) for k, v in headers) > 32768:
        return None
    return HTTPExchange(
        "completed", None, response.status, tuple(headers), response.body, True
    )


def response_binding(response: HTTPExchange) -> dict:
    return dict(
        status=response.status,
        body_bytes=len(response.body),
        body_sha256=hashlib.sha256(response.body).hexdigest(),
        headers_sha256=digest(response.headers),
    )


@dataclass
class ResourceContext:
    """Trusted in-process operation, never accepted by an agent request parser."""

    navigation_id: UUID
    sequence: int
    deadline: float
    body_limit: int
    active: Callable[[], bool] = field(repr=False)
    handoff: "ResponseHandoff | None" = field(default=None, repr=False)
    allow_redirects: bool = False


class ResponseHandoff:
    def __init__(self, response: HTTPExchange, receipt_sha256: str):
        self._response: HTTPExchange | None = response
        self.receipt_sha256 = receipt_sha256
        self._binding = response_binding(response)

    def __repr__(self) -> str:
        return "ResponseHandoff(private)"

    def consume(self, validate: Callable[[dict, str], None]) -> HTTPExchange:
        response, self._response = self._response, None
        if response is None or response_binding(response) != self._binding:
            raise WebIntegrityError("Invalid response handoff")
        validate(self._binding, self.receipt_sha256)
        return response
