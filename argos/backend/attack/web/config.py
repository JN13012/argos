"""Immutable, offline JSON configuration for external black-box missions.

URL checks are planning checks, not an HTTP security boundary. The transport
must recheck origins, DNS addresses, redirects and effects on every request.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import quote, unquote, urlsplit, urlunsplit

if TYPE_CHECKING:
    from argos.backend.core.mission_store import MissionRecord
    from argos.backend.core.missions import Mission

MAX_CONFIG_BYTES = 65536
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Expected nonempty text without surrounding whitespace")
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Whitespace, controls and backslashes are not supported")
    return value


def _host(value: str, *, private_profile: bool = False) -> str:
    value = _text(value)
    if "%" in value or value.endswith("."):
        raise ValueError("Scoped addresses and trailing dots are not supported")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            host = value.encode("idna").decode("ascii").lower()
            decoded_host = host.encode("ascii").decode("idna")
            # Reject IDNA mappings which differ from the supplied hostname.
            if not value.isascii() and decoded_host != value.lower():
                raise ValueError("Ambiguous IDNA host")
        except UnicodeError:
            raise ValueError("Invalid hostname") from None
        labels = host.split(".")
        if (
            len(host) > 253
            or (len(labels) < 2 and not private_profile)
            or not all(_LABEL.fullmatch(label) for label in labels)
            or re.fullmatch(r"[0-9]+|0x[0-9a-f]+", labels[-1])
            or (
                not private_profile
                and labels[-1]
                in {
                    "localhost",
                    "local",
                    "internal",
                    "home",
                    "onion",
                    "invalid",
                    "test",
                    "example",
                }
            )
        ):
            raise ValueError("Expected an unambiguous external hostname") from None
        return host
    if (
        (not address.is_global and not private_profile)
        or address.is_multicast
        or (address.is_reserved and not (private_profile and address.is_loopback))
        or (
            isinstance(address, ipaddress.IPv6Address)
            and address.ipv4_mapped is not None
        )
    ):
        raise ValueError("Only public unicast IP addresses are accepted")
    return str(address)


def _path(value: str) -> str:
    if not value.startswith("/") or re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Invalid absolute URL path")
    try:
        decoded = unquote(value, errors="strict")
    except UnicodeError:
        raise ValueError("Invalid path encoding") from None
    if (
        any(ord(c) < 32 or ord(c) == 127 for c in decoded)
        or any(c in decoded for c in "\\%;?#")
        or re.search(r"%2[fF]|%5[cC]", value)
        or "//" in decoded
        or any(part in {".", ".."} for part in decoded.split("/"))
    ):
        raise ValueError("Ambiguous URL paths are not supported")
    return quote(decoded, safe="/!$&'()*+,:=@-._~")


def _normalize_url(
    value: str, *, domain_seed: bool = False, private_profile: bool = False
) -> str:
    """Canonical HTTP(S) URL, without DNS lookup or credential-bearing errors."""
    value = _text(value)
    if domain_seed and "://" not in value:
        # A bare seed is a hostname, not a path, port or opaque URL.
        if any(c in value for c in "/:@?#"):
            raise ValueError("A bare seed must be a domain name")
        value = "https://" + value
    try:
        parts = urlsplit(value)
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not parts.netloc
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or "#" in value
        ):
            raise ValueError("Unsupported URL")
        host = _host(parts.hostname or "", private_profile=private_profile)
        authority_pattern = (
            r"\[[^\]]+\](?::[0-9]+)?" if ":" in host else r"[^:\[\]]+(?::[0-9]+)?"
        )
        if re.fullmatch(authority_pattern, parts.netloc) is None:
            raise ValueError("Ambiguous URL authority")
        port = parts.port
        if parts.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535):
            raise ValueError("Invalid port")
        if re.search(r"%(?![0-9a-fA-F]{2})|%0[adAD]", parts.query):
            raise ValueError("Invalid query encoding")
        scheme = parts.scheme.lower()
        authority = f"[{host}]" if ":" in host else host
        if port is not None and port != (443 if scheme == "https" else 80):
            authority += f":{port}"
        return urlunsplit(
            (scheme, authority, _path(parts.path or "/"), parts.query, "")
        )
    except (ValueError, UnicodeError):
        raise ValueError("Invalid external HTTP(S) URL") from None


def normalize_url(value: str, *, domain_seed: bool = False) -> str:
    """Canonical external URL; private evaluation uses a distinct signed profile."""
    return _normalize_url(value, domain_seed=domain_seed)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _strings(values: object, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > 256:
        raise ValueError("Expected a bounded list of strings")
    result = tuple(_text(v) for v in values)
    if (nonempty and not result) or len(set(result)) != len(result):
        raise ValueError("Expected unique entries")
    return result


def _keys(value: object, allowed: set[str], required: set[str] | None = None) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) - allowed
        or (required or set()) - set(value)
    ):
        raise ValueError("Missing or unsupported configuration fields")
    return value


@dataclass(frozen=True)
class WebScope:
    origins: tuple[str, ...]
    subdomain_roots: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        origins = []
        for value in _strings(self.origins, nonempty=True):
            url = self.normalize_url(value)
            parts = urlsplit(url)
            if parts.path != "/" or parts.query:
                raise ValueError("An origin cannot include a path or query")
            origins.append(_origin(url))
        roots = tuple(self.normalize_host(v) for v in _strings(self.subdomain_roots))
        for root in roots:
            try:
                ipaddress.ip_address(root)
            except ValueError:
                pass
            else:
                raise ValueError("A subdomain root must be a hostname")
            if not any(urlsplit(o).hostname == root for o in origins):
                raise ValueError("Each subdomain root needs an explicit base origin")
        excluded = tuple(_path(v) for v in _strings(self.excluded_paths))
        object.__setattr__(self, "origins", tuple(sorted(set(origins))))
        object.__setattr__(self, "subdomain_roots", tuple(sorted(set(roots))))
        object.__setattr__(self, "excluded_paths", tuple(sorted(set(excluded))))

    @staticmethod
    def normalize_url(value: str, *, domain_seed: bool = False) -> str:
        return normalize_url(value, domain_seed=domain_seed)

    @staticmethod
    def normalize_host(value: str) -> str:
        return _host(value)

    def permits_url(self, value: str) -> bool:
        """Offline scope check only; does not authorize an HTTP request."""
        try:
            url = self.normalize_url(value)
        except ValueError:
            return False
        parts = urlsplit(url)
        if any(
            parts.path == path.rstrip("/")
            or parts.path.startswith(path.rstrip("/") + "/")
            for path in self.excluded_paths
        ):
            return False
        if _origin(url) in self.origins:
            return True
        for root in self.subdomain_roots:
            for origin in self.origins:
                base = urlsplit(origin)
                if (
                    base.hostname == root
                    and parts.hostname is not None
                    and parts.hostname.endswith("." + root)
                    and parts.scheme == base.scheme
                    and parts.port == base.port
                ):
                    return True
        return False


@dataclass(frozen=True)
class WebLimits:
    duration_seconds: int = 1800
    max_requests: int = 5000
    requests_per_second: int = 2
    concurrency: int = 2
    request_timeout_seconds: int = 15
    response_bytes: int = 2097152

    def __post_init__(self) -> None:
        ceilings = (86400, 1000000, 100, 32, 120, 16777216)
        for value, ceiling in zip(asdict(self).values(), ceilings, strict=True):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("Limits must be positive bounded integers")
        if self.request_timeout_seconds > self.duration_seconds:
            raise ValueError("Request timeout exceeds mission duration")


@dataclass(frozen=True)
class WebAccess:
    credential_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        refs = _strings(self.credential_refs)
        if any(not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,127}", v) for v in refs):
            raise ValueError("Credentials must be opaque reference names, not values")
        object.__setattr__(self, "credential_refs", tuple(sorted(refs)))


@dataclass(frozen=True)
class WebEffects:
    allow_registration: bool = False
    allow_test_writes: bool = False

    def __post_init__(self) -> None:
        if any(type(v) is not bool for v in asdict(self).values()):
            raise ValueError("Effect permissions must be booleans")


@dataclass(frozen=True)
class WebMissionConfig:
    VERSION: ClassVar[int] = 1
    name: str
    seeds: tuple[str, ...]
    scope: WebScope
    schema_version: int = 1
    mode: str = "external_blackbox"
    access: WebAccess = field(default_factory=WebAccess)
    effects: WebEffects = field(default_factory=WebEffects)
    limits: WebLimits = field(default_factory=WebLimits)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not self.name.strip()
            or self.name != self.name.strip()
            or len(self.name) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in self.name)
        ):
            raise ValueError(
                "Expected a readable mission name of at most 128 characters"
            )
        if type(self.schema_version) is not int or self.schema_version != self.VERSION:
            raise ValueError("Unsupported configuration version")
        if self.mode != "external_blackbox":
            raise ValueError("Unsupported mission mode")
        if not (
            isinstance(self.scope, WebScope)
            and isinstance(self.access, WebAccess)
            and isinstance(self.effects, WebEffects)
            and isinstance(self.limits, WebLimits)
        ):
            raise ValueError("Expected typed web configuration sections")
        if self.VERSION == 1 and type(self.scope) is not WebScope:
            raise ValueError("Version 1 requires external web scope")
        seeds = tuple(
            self.scope.normalize_url(v, domain_seed=True)
            for v in _strings(self.seeds, nonempty=True)
        )
        if any(not self.scope.permits_url(v) for v in seeds):
            raise ValueError("Seeds must be inside the configured web scope")
        object.__setattr__(self, "seeds", tuple(sorted(set(seeds))))
        if len(self.to_json().encode()) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds size limit")

    @classmethod
    def from_dict(cls, value: object) -> WebMissionConfig:
        if isinstance(value, dict) and value.get("schema_version") == 5:
            from .browser_redirects import WebRedirectConfig

            return WebRedirectConfig.from_dict(value)
        if isinstance(value, dict) and value.get("schema_version") == 4:
            from .interaction import WebInteractionConfig

            return WebInteractionConfig.from_dict(value)
        if isinstance(value, dict) and value.get("schema_version") == 3:
            from .browser_config import WebBrowserConfig

            return WebBrowserConfig.from_dict(value)
        if isinstance(value, dict) and value.get("schema_version") == 2:
            from .execution_config import WebExecutionConfig

            return WebExecutionConfig.from_dict(value)
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
            },
            {"name", "seeds"},
        )
        seeds = tuple(
            normalize_url(v, domain_seed=True)
            for v in _strings(data["seeds"], nonempty=True)
        )
        scope_data = _keys(
            data.get("scope", {"origins": sorted({_origin(v) for v in seeds})}),
            {"origins", "subdomain_roots", "excluded_paths"},
            {"origins"},
        )
        access = _keys(data.get("access", {}), {"credential_refs"})
        effects = _keys(
            data.get("effects", {}), {"allow_registration", "allow_test_writes"}
        )
        limits = _keys(data.get("limits", {}), set(WebLimits.__dataclass_fields__))
        return cls(
            name=data["name"],
            seeds=seeds,
            scope=WebScope(**scope_data),
            access=WebAccess(**access),
            effects=WebEffects(**effects),
            limits=WebLimits(**limits),
            schema_version=data.get("schema_version", 1),
            mode=data.get("mode", "external_blackbox"),
        )

    @classmethod
    def from_json(cls, text: str) -> WebMissionConfig:
        if len(text.encode()) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds size limit")

        def unique(pairs: list[tuple[str, object]]) -> dict:
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate configuration key")
                result[key] = value
            return result

        try:
            return cls.from_dict(json.loads(text, object_pairs_hook=unique))
        except (TypeError, RecursionError, UnicodeError, ValueError):
            raise ValueError("Invalid web mission configuration") from None

    @classmethod
    def load(cls, path: str | Path) -> WebMissionConfig:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds size limit")
        try:
            return cls.from_json(raw.decode("utf-8"))
        except UnicodeError:
            raise ValueError("Configuration must be UTF-8 JSON") from None

    def to_json(self) -> str:
        return json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False
        )

    def to_record(self, mission: Mission) -> MissionRecord:
        """Bind the entire configuration to existing persistence and signatures."""
        from argos.backend.core.mission_store import MissionRecord
        from argos.backend.core.policy import Action

        if mission.title != self.name:
            raise ValueError("Mission title must match the configuration name")
        return MissionRecord(
            mission, None, frozenset({Action.WEB_HTTP_REQUEST}), self.to_json()
        )
