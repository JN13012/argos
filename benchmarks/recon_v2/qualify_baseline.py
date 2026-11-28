"""Measure fixed benign HTTP contracts or replay saved evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from statistics import median
from threading import Thread
from time import perf_counter, process_time
from wsgiref.simple_server import WSGIRequestHandler, make_server

from benchmarks.recon_v2 import fixtures
from benchmarks.recon_v2.audit import CATALOG, audit, read_json, sha256

PIN = "f4e73d282a321671a842fc175cf70cdc9281d5448443e3968a03f20c97d66a5f"
APPS = {"portal": fixtures.portal, "spa": fixtures.spa, "api": fixtures.api}


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass


def http_sample(name: str, rows: list[dict]) -> dict:
    """One fresh listener and a fixed set of documented requests."""
    start, cpu = perf_counter(), process_time()
    setup = start
    cleanup = None
    closed = None
    requests = []
    errors = []
    accepted: dict[str, bytes] = {}
    declared = False
    bound_loopback = False
    listener_closed = False
    try:
        with make_server(
            "127.0.0.1", 0, APPS[name], handler_class=QuietHandler
        ) as server:
            bound_loopback = server.socket.getsockname()[0] == "127.0.0.1"
            if not bound_loopback:
                raise RuntimeError("Fixture must use IPv4 loopback")
            thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                setup = perf_counter()
                for expected in rows:
                    before = perf_counter()
                    path = expected["path"]
                    method = expected["method"]
                    connection = HTTPConnection(
                        "127.0.0.1", server.server_port, timeout=3
                    )
                    try:
                        connection.request(method, path)
                        reply = connection.getresponse()
                        body = reply.read()
                        authenticated = reply.getheader("WWW-Authenticate") is not None
                        matches = reply.status == expected[
                            "status"
                        ] and authenticated == (
                            expected["authentication"] == "required"
                        )
                        requests.append(
                            dict(
                                path=path,
                                method=method,
                                status=reply.status,
                                seconds=perf_counter() - before,
                                bytes=len(body),
                                sha256=hashlib.sha256(body).hexdigest(),
                                matches=matches,
                            )
                        )
                        if matches:
                            accepted[path] = body
                    except (OSError, HTTPException) as error:
                        errors.append(dict(path=path, error=type(error).__name__))
                    finally:
                        connection.close()
            finally:
                cleanup = perf_counter()
                server.shutdown()
                thread.join()
        closed = perf_counter()
        listener_closed = server.socket.fileno() == -1
        if name == "api" and "/openapi.json" in accepted:
            declared = "get" in json.loads(accepted["/openapi.json"])["paths"].get(
                "/v1/books", {}
            )
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        errors.append(dict(error=type(error).__name__))
    return dict(
        http=dict(expected=len(rows), requests=requests, matched=len(accepted)),
        api=(
            dict(openapi_get_books=declared, get_books_observed="/v1/books" in accepted)
            if name == "api"
            else None
        ),
        generic_shell=(
            accepted.get("/") == accepted["/absent"]
            if name == "spa" and "/absent" in accepted
            else None
        ),
        network=dict(bound_loopback=bound_loopback, listener_closed=listener_closed),
        seconds=dict(
            setup=setup - start,
            cleanup=closed - cleanup if closed and cleanup else None,
        ),
        cpu_seconds=process_time() - cpu,
        process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        errors=errors,
    )


def controlled(catalog: dict) -> dict:
    result = {}
    for name, app_rows in catalog["fixtures"].items():
        runs = [http_sample(name, app_rows) for _ in range(3)]
        timings = [
            sum(row["seconds"] for row in trial["http"]["requests"]) for trial in runs
        ]
        states = [
            [
                (row["path"], row["status"], row["sha256"])
                for row in trial["http"]["requests"]
            ]
            for trial in runs
        ]
        passed = all(
            not trial["errors"]
            and trial["http"]["matched"] == len(app_rows)
            and trial["network"]["bound_loopback"]
            and trial["network"]["listener_closed"]
            and (name != "spa" or trial["generic_shell"])
            and (name != "api" or all(trial["api"].values()))
            for trial in runs
        ) and all(state == states[0] for state in states)
        result[name] = dict(
            status="passed" if passed else "partial",
            http_seconds=dict(
                median=median(timings), low=min(timings), high=max(timings)
            ),
            repetitions=runs,
        )
    return result


def historical(root: Path) -> dict:
    result = audit(root)
    for lab in result["trials"].values():
        old, new = lab["m27"], lab["m271"]
        lab["deltas"] = {
            "seconds": new["archived_cost"]["duration_seconds"]
            - old["archived_cost"]["duration_seconds"],
            "tickets": new["http"]["tickets"] - old["http"]["tickets"],
            "phases_seconds": {
                name: phase["seconds"] - old["archived_phases"][name]["seconds"]
                for name, phase in new["archived_phases"].items()
            },
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path)
    args = parser.parse_args()
    if sha256(CATALOG) != PIN:
        raise ValueError("M4.2b reference differs from frozen corpus")
    if args.archives is not None:
        result = {"archives": historical(args.archives)}
        success = True
    else:
        result = {"fixtures": controlled(read_json(CATALOG))}
        success = all(app["status"] == "passed" for app in result["fixtures"].values())
    print(
        json.dumps({"catalog_sha256": PIN, "python": sys.version, **result}, indent=2)
    )
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
