"""Private navigation contracts, distinct from HTTP requests and permissions."""

from dataclasses import dataclass, field
from uuid import UUID, uuid4

from .browser_config import WebBrowserLimits
from .config import _text
from .contracts import _digest, _integer, _uuid


@dataclass(frozen=True)
class NavigationRequest:
    mission_id: UUID
    run_id: UUID
    route_id: UUID
    url: str = field(repr=False)
    navigation_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        for value in (self.mission_id, self.run_id, self.route_id, self.navigation_id):
            _uuid(value)
        _text(self.url)
        if len(self.url.encode()) > 8192:
            raise ValueError("Navigation URL exceeds contract limit")


@dataclass(frozen=True)
class NavigationUsage:
    mission_id: UUID
    navigations_used: int = 0
    in_flight: int = 0

    def __post_init__(self) -> None:
        _uuid(self.mission_id)
        _integer(self.navigations_used)
        _integer(self.in_flight)
        if self.in_flight > self.navigations_used:
            raise ValueError("In-flight navigations exceed reservations")


@dataclass(frozen=True)
class NavigationPlan:
    """Offline plan, not a durable reservation or permission to launch."""

    request: NavigationRequest = field(repr=False)
    configuration_sha256: str
    limits: WebBrowserLimits
    timeout_ms: int
    effective_body_bytes: int

    @property
    def transport_enabled(self) -> bool:
        return False


@dataclass(frozen=True)
class NavigationSnapshot:
    id: UUID
    mission_id: UUID
    run_id: UUID
    route_id: UUID
    state: str
    reason: str
    configuration_sha256: str
    record_sha256: str

    def __post_init__(self) -> None:
        for value in (self.id, self.mission_id, self.run_id, self.route_id):
            _uuid(value)
        _digest(self.configuration_sha256)
        _digest(self.record_sha256)
        if (self.state, self.reason) not in {
            ("pending", "pending"),
            ("reserved", "reserved"),
            ("running", "running"),
            ("completed", "observed"),
            ("partial", "limited"),
            ("failed", "isolation_unavailable"),
            ("failed", "profile_changed"),
            ("failed", "request_timeout"),
            ("cancelled", "cancelled"),
            ("interrupted", "interrupted"),
        }:
            raise ValueError("Unsupported navigation state")
