"""Signed destination profiles; numeric checks never resolve a hostname."""

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from argos.backend.core.network_policy import GUEST_CIDR, NetworkPolicy

from .config import WebScope, _host, _normalize_url, _strings

_PRIVATE_RANGES = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.1/32",
        "::1/128",
        "fc00::/7",
    )
)
_TECHNICAL_RANGES = (
    ipaddress.ip_network(GUEST_CIDR),
    ipaddress.ip_network("fd00::/64"),
)


class DestinationKind(StrEnum):
    EXTERNAL = "external"
    EVALUATION_PRIVATE = "evaluation_private"


@dataclass(frozen=True)
class DestinationProfile:
    kind: DestinationKind = DestinationKind.EXTERNAL
    networks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.kind) is not DestinationKind:
            raise ValueError("Expected a destination profile kind")
        networks = _strings(self.networks)
        if self.kind is DestinationKind.EXTERNAL:
            if networks:
                raise ValueError("External profiles cannot add private networks")
        elif not 1 <= len(networks) <= 16:
            raise ValueError("Private evaluation requires 1 to 16 explicit networks")
        canonical = []
        for value in networks:
            network = ipaddress.ip_network(value, strict=True)
            if str(network) != value or not any(
                network.version == allowed.version
                and int(network.network_address) >= int(allowed.network_address)
                and int(network.broadcast_address) <= int(allowed.broadcast_address)
                for allowed in _PRIVATE_RANGES
            ):
                raise ValueError(
                    "Only canonical private evaluation networks are supported"
                )
            if any(
                network.version == reserved.version and network.overlaps(reserved)
                for reserved in _TECHNICAL_RANGES
            ):
                raise ValueError("Evaluation networks overlap worker infrastructure")
            canonical.append(str(network))
        object.__setattr__(self, "networks", tuple(sorted(canonical)))

    def permits_address(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
            NetworkPolicy(value, (443,))
        except (TypeError, ValueError):
            return False
        if self.kind is DestinationKind.EXTERNAL:
            return address.is_global and not address.is_reserved
        return any(address in ipaddress.ip_network(net) for net in self.networks)


@dataclass(frozen=True)
class PrivateWebScope(WebScope):
    """Syntax for private evaluation only; the signed profile still checks IPs."""

    @staticmethod
    def normalize_url(value: str, *, domain_seed: bool = False) -> str:
        return _normalize_url(value, domain_seed=domain_seed, private_profile=True)

    @staticmethod
    def normalize_host(value: str) -> str:
        return _host(value, private_profile=True)
