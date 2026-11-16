"""System resolver child. No application dependencies or executable input."""

import ipaddress
import json
import socket
import sys


def main() -> int:
    try:
        settings = json.loads(sys.stdin.buffer.read(4096))
        addresses = set()
        for entry in socket.getaddrinfo(
            settings["hostname"], None, type=socket.SOCK_STREAM
        ):
            address = ipaddress.ip_address(entry[4][0])
            addresses.add(str(address))
            if len(addresses) > settings["maximum"]:
                return 2
        if not addresses:
            return 2
        sys.stdout.write(json.dumps(sorted(addresses)))
        return 0
    except (OSError, ValueError, KeyError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
