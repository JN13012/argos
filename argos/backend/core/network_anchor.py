"""Trusted outer user/net namespace: install firewall before bringing up TAP.

Only the guardian owns stdin. No commands or API are exposed to the tool.
"""

from __future__ import annotations

import json
import subprocess
import sys

from network_policy import NetworkPolicy


def main() -> None:
    decoded = json.loads(sys.argv[1])
    policy = NetworkPolicy(decoded["target_ip"], tuple(decoded["ports"]))
    subprocess.run(
        ["/usr/sbin/nft", "-f", "-"],
        input=policy.nft_rules(),
        text=True,
        check=True,
        timeout=2,
    )
    # Read the rules back from the kernel before signalling readiness.
    installed = subprocess.run(
        ["/usr/sbin/nft", "--json", "list", "table", "inet", "argos"],
        capture_output=True,
        text=True,
        check=True,
        timeout=2,
    )
    chains = [
        item["chain"]
        for item in json.loads(installed.stdout)["nftables"]
        if "chain" in item
    ]
    if len(chains) != 3 or any(chain["policy"] != "drop" for chain in chains):
        raise RuntimeError("Network firewall is not active")
    print("ready", flush=True)
    if sys.stdin.readline() != "configure\n":
        return
    for args in (
        ("-6", "addr", "flush", "dev", "tap0", "scope", "link"),
        ("-6", "addr", "add", "fe80::100/64", "dev", "tap0", "nodad"),
        ("-6", "addr", "add", "fd00::100/64", "dev", "tap0", "nodad"),
        ("-6", "route", "replace", "default", "via", "fd00::2", "dev", "tap0"),
    ):
        subprocess.run(["/usr/sbin/ip", *args], check=True, timeout=2)
    print("configured", flush=True)
    # EOF means that the guardian has disappeared or completed the job.
    sys.stdin.read()


if __name__ == "__main__":
    main()
