"""Literal TCP destinations for the private rootless worker network."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

NETWORK_VERSION = "argos-network-v1"
GUEST_CIDR = "10.253.0.0/24"


@dataclass(frozen=True)
class NetworkPolicy:
    target_ip: str
    ports: tuple[int, ...]

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.target_ip)
        if (
            str(address) != self.target_ip
            or address.is_unspecified
            or address.is_multicast
        ):
            raise ValueError("A canonical unicast destination is required")
        if (
            address.is_link_local
            or getattr(address, "scope_id", None) is not None
            or getattr(address, "ipv4_mapped", None) is not None
            or address in ipaddress.ip_network(GUEST_CIDR)
            or address in ipaddress.ip_network("fd00::/64")
            or (address.is_loopback and self.target_ip not in ("127.0.0.1", "::1"))
            or self.target_ip == "255.255.255.255"
        ):
            raise ValueError("Destination conflicts with the private worker network")
        if (
            not 1 <= len(self.ports) <= 32
            or tuple(sorted(set(self.ports))) != self.ports
        ):
            raise ValueError("Expected 1 to 32 sorted unique TCP ports")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in self.ports):
            raise ValueError("Invalid TCP port")

    @property
    def connect_ip(self) -> str:
        # libslirp's gateways represent the host's exact loopback endpoints.
        return {"127.0.0.1": "10.253.0.2", "::1": "fd00::2"}.get(
            self.target_ip, self.target_ip
        )

    def nft_rules(self) -> str:
        family = "ip6" if ":" in self.connect_ip else "ip"
        ports = ",".join(map(str, self.ports))
        nd_out = (
            'oifname "tap0" ip6 daddr { ff02::/16, fd00::/64, fe80::/64 } '
            "ip6 hoplimit 255 icmpv6 type "
            "{ nd-neighbor-solicit, nd-neighbor-advert } accept"
        )
        nd_in = (
            'iifname "tap0" ip6 hoplimit 255 icmpv6 type '
            "{ nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
        )
        return f"""table inet argos {{
 chain output {{ type filter hook output priority filter; policy drop;
  {family} daddr {self.connect_ip} tcp dport {{ {ports} }} counter accept
  {nd_out}
 }}
 chain input {{ type filter hook input priority filter; policy drop;
  iifname "tap0" ct state established,related accept
  {nd_in}
 }}
 chain forward {{ type filter hook forward priority filter; policy drop; }}
}}"""
