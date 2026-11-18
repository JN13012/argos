"""Version 2 HTTP planning contracts; no implicit v1 upgrade or live transport."""

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import ClassVar
from urllib.parse import urlsplit

from .config import (
    WebAccess,
    WebEffects,
    WebLimits,
    WebMissionConfig,
    WebScope,
    _keys,
    _origin,
    _strings,
)
from .destinations import DestinationKind, DestinationProfile, PrivateWebScope

HTTP_CAPABILITIES = frozenset({"http.discover", "http.check_redirect"})


@dataclass(frozen=True)
class WebExecutionLimits:
    dns_timeout_seconds: int = 5
    max_dns_addresses: int = 16
    response_header_bytes: int = 32768
    response_header_count: int = 100
    header_line_bytes: int = 8192
    max_redirects: int = 5
    max_urls: int = 1000
    max_depth: int = 5
    query_variants: int = 10
    evidence_bytes: int = 67108864
    url_bytes: int = 8192
    max_retry_after_seconds: int = 60

    def __post_init__(self) -> None:
        ceilings = (5, 16, 32768, 100, 8192, 5, 1000, 5, 10, 67108864, 8192, 60)
        for name, ceiling in zip(asdict(self), ceilings, strict=True):
            value = getattr(self, name)
            minimum = 0 if name in {"max_redirects", "max_depth"} else 1
            if type(value) is not int or not minimum <= value <= ceiling:
                raise ValueError("Invalid bounded HTTP execution limit")
        if self.header_line_bytes > self.response_header_bytes:
            raise ValueError("Header line limit exceeds total header budget")


@dataclass(frozen=True)
class WebExecutionConfig(WebMissionConfig):
    VERSION: ClassVar[int] = 2
    ALLOWED_CAPABILITIES: ClassVar[frozenset[str]] = HTTP_CAPABILITIES
    schema_version: int = 2
    capabilities: tuple[str, ...] = ("http.discover",)
    destination: DestinationProfile = field(default_factory=DestinationProfile)
    execution: WebExecutionLimits = field(default_factory=WebExecutionLimits)

    def __post_init__(self) -> None:
        if not isinstance(self.destination, DestinationProfile) or not isinstance(
            self.execution, WebExecutionLimits
        ):
            raise ValueError("Expected typed HTTP execution sections")
        capabilities = _strings(self.capabilities, nonempty=True)
        if not set(capabilities) <= self.ALLOWED_CAPABILITIES:
            raise ValueError("Unsupported HTTP capability")
        object.__setattr__(self, "capabilities", tuple(sorted(capabilities)))
        expected_scope = (
            PrivateWebScope
            if self.destination.kind is DestinationKind.EVALUATION_PRIVATE
            else WebScope
        )
        if type(self.scope) is not expected_scope:
            raise ValueError("Web scope must match the signed destination profile")
        super().__post_init__()
        if self.execution.dns_timeout_seconds > self.limits.request_timeout_seconds:
            raise ValueError("DNS deadline exceeds request deadline")
        for origin in self.scope.origins:
            try:
                literal = ipaddress.ip_address(urlsplit(origin).hostname or "")
            except ValueError:
                continue
            if not self.destination.permits_address(str(literal)):
                raise ValueError("Literal origin is outside the destination profile")

    @classmethod
    def from_dict(cls, value: object) -> "WebExecutionConfig":
        return cls(**cls._fields(value))

    @classmethod
    def _fields(
        cls, value: object, *, browser: bool = False, interaction: bool = False
    ) -> dict:
        """Shared parsing; version-specific fields remain explicitly closed."""
        data = _keys(
            value,
            {
                "schema_version",
                "name",
                "mode",
                "seeds",
                "scope",
                "access",
                "effects",
                "limits",
                "capabilities",
                "destination",
                "execution",
            }
            | ({"browser"} if browser else set())
            | ({"interaction"} if interaction else set()),
            {"schema_version", "name", "seeds", "capabilities"}
            | ({"browser"} if browser else set())
            | ({"interaction"} if interaction else set()),
        )
        dest = _keys(data.get("destination", {}), {"kind", "networks"})
        destination = DestinationProfile(
            DestinationKind(dest.get("kind", "external")), dest.get("networks", ())
        )
        scope_type = (
            PrivateWebScope
            if destination.kind is DestinationKind.EVALUATION_PRIVATE
            else WebScope
        )
        seeds = tuple(
            scope_type.normalize_url(v, domain_seed=True)
            for v in _strings(data["seeds"], nonempty=True)
        )
        scope_data = _keys(
            data.get("scope", {"origins": sorted({_origin(v) for v in seeds})}),
            {"origins", "subdomain_roots", "excluded_paths"},
            {"origins"},
        )
        return dict(
            name=data["name"],
            seeds=seeds,
            scope=scope_type(**scope_data),
            schema_version=data["schema_version"],
            mode=data.get("mode", "external_blackbox"),
            access=WebAccess(**_keys(data.get("access", {}), {"credential_refs"})),
            effects=WebEffects(
                **_keys(
                    data.get("effects", {}), {"allow_registration", "allow_test_writes"}
                )
            ),
            limits=WebLimits(
                **_keys(data.get("limits", {}), set(WebLimits.__dataclass_fields__))
            ),
            capabilities=data["capabilities"],
            destination=destination,
            execution=WebExecutionLimits(
                **_keys(
                    data.get("execution", {}),
                    set(WebExecutionLimits.__dataclass_fields__),
                )
            ),
        )
