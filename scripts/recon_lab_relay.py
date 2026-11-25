"""Developer lab bridge: internal Docker TCP -> shared Unix socket -> loopback.

Docker internal networks intentionally have no default route. This bridge keeps
that property when the daemon cannot publish ports from an internal network.
Run one Unix relay per isolated lab; never attach it to an external network.
"""

import argparse
import select
import signal
import socket
import socketserver
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--listen", type=int, help="Host loopback TCP port")
    mode.add_argument("--target", help="Internal Docker service:port")
    args = parser.parse_args()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                if args.target:
                    host, port = args.target.rsplit(":", 1)
                    peer = socket.create_connection((host, int(port)), timeout=10)
                else:
                    peer = socket.socket(socket.AF_UNIX)
                    peer.settimeout(10)
                    peer.connect(args.socket)
                with peer:
                    while True:
                        ready, _, _ = select.select([self.request, peer], [], [], 30)
                        if not ready:
                            return
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (peer if source is self.request else self.request).sendall(
                                data
                            )
            except (OSError, TimeoutError):
                return

    class TCP(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class Unix(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True

    def terminate(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    server = (
        Unix(args.socket, Handler)
        if args.target
        else TCP(("127.0.0.1", args.listen), Handler)
    )
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if args.target:
            Path(args.socket).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
