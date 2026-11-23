"""One bounded tool relay. Every external GET owns a normal HTTP ticket."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.policy import WebPolicyError
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.store import WebStore


class RelayServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2)
        return connection, address


class EnumerationRelay:
    def __init__(
        self, runtime, mission_id, seed, *, active, maximum, run_id=None, entries=()
    ):
        self.runtime = runtime
        self.mission_id = mission_id
        parts = urlsplit(seed)
        # Explicit seed directory only; never expand a scoped /app to the host /.
        self.base = urlunsplit(
            (parts.scheme, parts.netloc, parts.path.rstrip("/") + "/", "", "")
        )
        self.active = active
        self.maximum = maximum
        self.run_id = run_id
        self.entries = frozenset(entries)
        self.served_entries: set[str] = set()
        self.token = uuid4().hex
        self.observations: list[dict] = []
        self.errors: list[str] = []
        self.requests = 0
        self.pending_request = None
        self.server = RelayServer(("127.0.0.1", 0), self._handler())
        self.server.timeout = 0.1
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _handler(self):
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.connection.settimeout(2)
                prefix = f"/{relay.token}/"
                if not self.path.startswith(prefix) or not relay.active():
                    self.send_error(403)
                    return
                relay.requests = min(relay.requests + 1, relay.maximum + 1)
                if relay.requests > relay.maximum:
                    if "relay_budget_exhausted" not in relay.errors:
                        relay.errors.append("relay_budget_exhausted")
                    self.send_error(429)
                    return
                relative = self.path[len(prefix) :]
                # Gobuster also probes the directory and a UUID for wildcard detection.
                from .tools import words

                try:
                    if relative:
                        words((relative,))
                    target = relay.base + relative
                    request = WebRequest(relay.mission_id, target)
                    responses = []
                    route_id = None
                    if relay.run_id and relative in relay.entries:
                        config = relay.runtime.policy.configuration(relay.mission_id)
                        with WebStore(relay.runtime.database) as store:
                            frontier = Frontier(store.db)
                            frontier.enqueue_candidates(
                                relay.run_id, config, relay.runtime.owner, [target]
                            )
                            route = next(
                                (
                                    r
                                    for r in frontier.routes(relay.run_id)
                                    if r["url"] == target
                                ),
                                None,
                            )
                            if route is None or route["state"] in {
                                "blocked",
                                "excluded",
                            }:
                                relay.errors.append(
                                    route["reason"] if route else "frontier_limit"
                                )
                                self.send_error(403)
                                return
                            if route and route["state"] == "queued":
                                from uuid import UUID

                                route_id = UUID(route["id"])
                    rid = relay.runtime.submit(request, _route_id=route_id)
                    relay.pending_request = rid
                    if relay.closed.is_set():
                        relay.runtime.cancel(rid)
                    snapshot = relay.runtime.run(rid, _responses=responses)
                    relay.pending_request = None
                    item: dict = dict(
                        request_id=str(rid),
                        url_sha256=digest(target),
                        state=snapshot.state,
                        error=snapshot.error,
                        evidence_sha256=snapshot.evidence_sha256,
                    )
                    proof = relay.runtime.evidence(rid)
                    item["response"] = proof["response"] if proof else None
                    relay.observations.append(item)
                    if not responses or not relay.active():
                        relay.errors.append(snapshot.error or "response_unavailable")
                        self.send_error(502)
                        return
                    response = responses[0]
                    assert response.status is not None
                    if relative in relay.entries:
                        relay.served_entries.add(relative)
                    # Only status and body are handed to tools.
                    self.send_response(response.status)
                    self.send_header("Content-Length", str(len(response.body)))
                    self.end_headers()
                    self.wfile.write(response.body)
                except WebPolicyError as error:
                    relay.errors.append(error.code.value)
                    self.send_error(403)
                except WebIntegrityError:
                    relay.errors.append("storage_failed")
                    relay.runtime.stop.set()
                    self.close_connection = True
                except ValueError:
                    relay.errors.append("invalid_tool_path")
                    self.send_error(400)
                except Exception:
                    relay.errors.append("relay_failed")
                    relay.runtime.stop.set()
                    self.close_connection = True

        return Handler

    def _serve(self):
        while not self.closed.is_set():
            self.server.handle_request()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.closed.set()
        if self.pending_request is not None and not self.runtime._broken:
            self.runtime.cancel(self.pending_request)
        self.thread.join(timeout=15)
        self.server.server_close()
        if self.thread.is_alive():
            self.runtime.stop.set()
            raise RuntimeError("Enumeration relay did not stop")
