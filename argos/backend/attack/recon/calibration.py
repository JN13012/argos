"""Reuse verified discovery controls; never fetch a calibration or expand scope."""

from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.store import WebStore


def verify_control(store, mission_id, seed, request_id):
    rid = UUID(request_id)
    request, row = store.private_request(rid)
    proof = store.evidence(rid)
    frontier = Frontier(store.db)
    route = frontier.route_for(rid)
    capture = frontier.capture(rid) if route else None
    response = (proof or {}).get("response") or {}
    parts = urlsplit(seed)
    base = urlunsplit(
        (parts.scheme, parts.netloc, parts.path.rstrip("/") + "/", "", "")
    )
    # Discovery's control is origin-root only. It is not a directory-specific
    # control for a scoped /app/ seed, even when the origins match.
    if (
        request.mission_id != mission_id
        or request.method != "GET"
        or row["state"] != "completed"
        or route is None
        or route["kind"] != "probe"
        or request.url.rsplit("/", 1)[0] + "/" != base
        or urlsplit(request.url).query
        or not capture
        or not capture.get("fingerprint")
        or not response.get("body_complete")
        or type(response.get("status")) is not int
        or not 200 <= response["status"] < 300
    ):
        return None
    run = frontier.run(UUID(route["run_id"]))
    if (
        run["mission_id"] != str(mission_id)
        or run["configuration_sha256"] != row["configuration_sha256"]
        or proof.get("discovery") != capture["public"]
    ):
        raise WebIntegrityError("Enumeration calibration binding differs")
    return dict(
        request_id=str(rid),
        evidence_sha256=digest(proof),
        length=response["retained_bytes"],
    )


def controls(database, mission_id, seed, *, run_id=None):
    """At most four controls from at most sixteen recent mission discoveries."""
    with WebStore(database, readonly=True) as store:
        exists = store.db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='web_discovery_runs'"
        ).fetchone()
        if not exists:
            return []
        ids = (
            [str(run_id)]
            if run_id
            else [
                row[0]
                for row in store.db.execute(
                    "SELECT id FROM web_discovery_runs WHERE mission_id=? "
                    "ORDER BY rowid DESC LIMIT 16",
                    (str(mission_id),),
                )
            ]
        )
        found = []
        for rid in ids:
            for route in Frontier(store.db).routes(UUID(rid)):
                if route["kind"] != "probe" or not route["request_id"]:
                    continue
                item = verify_control(store, mission_id, seed, route["request_id"])
                if item and item not in found:
                    found.append(item)
                if len(found) == 4:
                    return found
        return found
