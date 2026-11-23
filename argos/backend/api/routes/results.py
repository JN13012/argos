"""Read-only, allowlisted projections of existing mission SQLite stores."""

import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from argos.backend.attack.pentest.evidence_store import (
    EvidenceIntegrityError,
    EvidenceStore,
)
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.store import WebStore
from argos.backend.core.config import ResultSource, Settings
from argos.backend.core.mission_store import MissionStore

MAX_REPORT = 16 * 1024 * 1024


def public_code(value):
    return (
        value
        if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value)
        else "unavailable"
    )


def safe_url(value: str) -> str:
    """No credentials, fragments or query values in the public projection."""
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return "[URL unavailable]"
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host += f":{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


@contextmanager
def database(source: ResultSource):
    # Never create or migrate a database. One consistent read transaction per view.
    path = Path(source.database)
    if path.is_symlink() or not path.is_file():
        raise HTTPException(503, "Result source unavailable")
    with WebStore(path, readonly=True) as web:
        web.db.execute("PRAGMA query_only=ON")
        web.db.execute("BEGIN")
        yield web


def exists(connection, table):
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        is not None
    )


def overview(connection, mission_id) -> dict:
    record = MissionStore("", connection=connection).get(mission_id)
    if record is None:
        raise HTTPException(404, "Mission not found")
    config = json.loads(record.web_configuration) if record.web_configuration else None
    return dict(
        id=str(mission_id),
        title=record.mission.title,
        state=record.mission.state.value,
        kind="web" if config else "network",
        targets=[safe_url(v) for v in config["seeds"]]
        if config
        else list(record.scope.networks)
        if record.scope
        else [],
    )


def classification(route, response, *, probe=False):
    if probe:
        return "probe"
    if not response:
        return "unverified"
    status = response.get("status") or 0
    if status >= 400:
        return "http_error"
    if route and route["reason"] == "suspected_soft_404":
        return "spa_generic"
    if route and route["reason"] in {"non_html", "javascript", "openapi", "spa_shell"}:
        return "response_observed"
    if route and route["state"] == "visited" and 200 <= status < 300:
        return "route_observed"
    return "unverified"


def details(web, source, mission_id):
    connection = web.db
    result = overview(connection, mission_id)
    result.update(
        runs=[],
        tools=[],
        ports=[],
        requests=[],
        routes=[],
        evidence=[],
        technologies=[],
        limitations=[
            "Observations uniquement ; aucune vulnérabilité confirmée.",
            "Empreintes de cohérence locale ; authenticité non signée.",
            "Sorties brutes Gobuster/ffuf et corps HTTP complets non archivés.",
            "Pas de rendu JavaScript, session authentifiée ou méthode hors GET.",
            "Valeurs des paramètres et sorties brutes omises de cette vue.",
        ],
        wordlist_provenance=source.wordlist_provenance,
        verification="verified",
        started_at=None,
        finished_at=None,
        duration_seconds=None,
    )
    times = []
    stage_requests = {}
    nmap_refs = {}
    if exists(connection, "recon_runs"):
        for row in connection.execute("SELECT * FROM recon_runs"):
            value = json.loads(row["payload"])
            if value.get("mission_id") != str(mission_id):
                continue
            if digest(value) != row["sha256"] or value["id"] != row["id"]:
                raise WebIntegrityError("Recon snapshot differs")
            result["runs"].append(
                dict(
                    id=value["id"],
                    status=value["status"],
                    created_at=value["created_at"],
                )
            )
            times.append(value["created_at"])
            for stage in value["stages"]:
                tool = stage["tool"]
                result["tools"].append(
                    {
                        key: stage[key]
                        for key in (
                            "tool",
                            "job_id",
                            "state",
                            "reason",
                            "exit_code",
                            "errors",
                            "wordlist_entries",
                            "entries_with_response",
                            "wordlist_sha256",
                            "binary_sha256",
                            "stdout_sha256",
                            "stderr_sha256",
                        )
                        if key in stage
                    }
                )
                if tool == "nmap" and stage.get("job_id"):
                    nmap_refs[stage["job_id"]] = stage.get("evidence_sha256")
                for req in stage.get("requests", []):
                    stage_requests[req["request_id"]] = (tool, req["evidence_sha256"])
    if nmap_refs and not exists(connection, "pentest_scan_evidence"):
        raise EvidenceIntegrityError("Missing scan store")
    if exists(connection, "pentest_scan_evidence"):
        store = EvidenceStore("", connection=connection)
        job_ids = set(store.list_for_mission(mission_id)) | {UUID(v) for v in nmap_refs}
        for job_id in sorted(job_ids, key=str):
            proof = store.get_verified(job_id)
            if proof is None or (
                str(job_id) in nmap_refs
                and nmap_refs[str(job_id)] != proof.receipt.record_sha256
            ):
                raise EvidenceIntegrityError("Missing or changed scan evidence")
            scan = proof.record
            for tool in result["tools"]:
                if tool.get("job_id") == str(job_id):
                    tool["exit_code"] = scan.exit_code
            times.extend([scan.finished_at.isoformat()])
            if scan.started_at:
                times.append(scan.started_at.isoformat())
            result["evidence"].append(
                dict(
                    id=str(job_id),
                    tool="nmap",
                    verification="verified",
                    sha256=proof.receipt.record_sha256,
                    xml_sha256=proof.receipt.xml_sha256,
                    started_at=scan.started_at.isoformat() if scan.started_at else None,
                    recorded_at=scan.finished_at.isoformat(),
                    state=scan.state,
                    exit_code=scan.exit_code,
                    error=public_code(scan.error) if scan.error else None,
                )
            )
            if not result["runs"]:
                result["tools"].append(
                    dict(tool="nmap", state=scan.state, exit_code=scan.exit_code)
                )
            if scan.observation:
                for port in scan.observation.ports:
                    result["ports"].append(
                        dict(
                            target=port.host,
                            port=port.port,
                            protocol=port.protocol,
                            state=port.state,
                            service=port.service,
                            version=port.version,
                            confidence="unqualified",
                            confidence_note=(
                                "Service archivé, confiance non qualifiée. "
                                "Une table de ports ne confirme pas le logiciel."
                            ),
                        )
                    )
    if exists(connection, "web_discovery_runs"):
        frontier = Frontier(connection)
        for row in connection.execute(
            "SELECT id FROM web_discovery_runs WHERE mission_id=?", (str(mission_id),)
        ):
            run_id = UUID(row[0])
            run = frontier.run(run_id)
            if not result["runs"]:
                result["runs"].append(
                    dict(
                        id=str(run_id),
                        status=run["status"],
                        created_at=run["created_at"],
                    )
                )
            for route in frontier.routes(run_id):
                result["routes"].append(
                    dict(
                        id=route["id"],
                        url=safe_url(route["url"]),
                        state=route["state"],
                        reason=route["reason"],
                        kind=route["kind"],
                        request_id=route["request_id"],
                        provenance=route.get("provenance", []),
                        verification="not_requested"
                        if not route["request_id"]
                        else "http_requested",
                    )
                )
    route_map = {r["request_id"]: r for r in result["routes"]}
    if stage_requests and not exists(connection, "web_http_requests"):
        raise WebIntegrityError("Missing HTTP store")
    observed_requests = set()
    if exists(connection, "web_http_requests"):
        for row in connection.execute(
            "SELECT id FROM web_http_requests WHERE mission_id=?", (str(mission_id),)
        ):
            rid = UUID(row[0])
            observed_requests.add(str(rid))
            request, _ = web.private_request(rid)
            snapshot = web.snapshot(rid)
            proof = web.evidence(rid)
            tool, expected = stage_requests.get(str(rid), ("http", None))
            if expected and (not proof or digest(proof) != expected):
                raise WebIntegrityError("Tool receipt differs")
            route = route_map.get(str(rid))
            response = proof["response"] if proof else None
            recorded_at = proof["recorded_at"] if proof else None
            if recorded_at:
                times.append(recorded_at)
            category = classification(
                route,
                response,
                probe=bool(
                    route
                    and route["kind"] == "probe"
                    or tool == "gobuster"
                    and not route
                ),
            )
            result["requests"].append(
                dict(
                    id=str(rid),
                    url=safe_url(request.url),
                    method=request.method,
                    tool=tool,
                    state=snapshot.state,
                    error=snapshot.error,
                    http_status=response.get("status") if response else None,
                    classification=category,
                    reason=route["reason"] if route else "tool_precheck",
                    provenance=route.get("provenance", []) if route else [],
                    wordlist_provenance=source.wordlist_provenance
                    if tool in {"gobuster", "ffuf"}
                    else "not_applicable",
                    confidence="observed_response" if proof else "unverified",
                    evidence_sha256=snapshot.evidence_sha256,
                    verification="verified" if proof else "not_available",
                    recorded_at=recorded_at,
                )
            )
    if not set(stage_requests) <= observed_requests:
        raise WebIntegrityError("Missing tool request")
    if not result["evidence"] and not any(
        item["verification"] == "verified" for item in result["requests"]
    ):
        result["verification"] = "not_available"
    if times:
        instants = sorted(datetime.fromisoformat(v) for v in times)
        result.update(
            started_at=instants[0].isoformat(),
            finished_at=instants[-1].isoformat(),
            duration_seconds=round((instants[-1] - instants[0]).total_seconds(), 3),
        )
    for tool in result["tools"]:
        for key in ("tool", "state", "reason"):
            if key in tool:
                tool[key] = public_code(tool[key])
        if "errors" in tool:
            tool["errors"] = [public_code(value) for value in tool["errors"]]
    result["duration_note"] = (
        "Intervalle des preuves ; durée exacte du pipeline non archivée."
    )
    result["limitations"].append("Aucune identification technologique fiable archivée.")
    result["requests"].sort(key=lambda r: r["recorded_at"] or "")
    return result


def results_router(settings: Settings):
    router = APIRouter(prefix="/results", tags=["results"])

    def source_for(source_id):
        source = settings.result_sources.get(source_id)
        if source is None:
            raise HTTPException(404, "Result source not found")
        return source

    @router.get("")
    def catalog():
        sources = []
        for source_id, source in settings.result_sources.items():
            item: dict = dict(
                id=source_id, label=source.label, state="available", missions=[]
            )
            try:
                with database(source) as web:
                    connection = web.db
                    rows = connection.execute(
                        "SELECT id FROM pentest_missions LIMIT 501"
                    ).fetchall()
                    item["truncated"] = len(rows) > 500
                    item["missions"] = [
                        overview(connection, UUID(r[0])) for r in rows[:500]
                    ]
            except (sqlite3.Error, ValueError, OSError, HTTPException):
                item.update(state="unavailable", missions=[])
            sources.append(item)
        return dict(sources=sources)

    @router.get("/{source_id}/missions/{mission_id}")
    def mission(source_id: str, mission_id: UUID):
        source = source_for(source_id)
        try:
            with database(source) as web:
                value = details(web, source, mission_id)
        except (WebIntegrityError, EvidenceIntegrityError):
            raise HTTPException(409, "Stored evidence verification failed") from None
        except (sqlite3.Error, ValueError, KeyError, TypeError, IndexError, OSError):
            raise HTTPException(503, "Result source unavailable") from None
        value["reports"] = [
            dict(
                id=key,
                label=report.label,
                url=f"/api/v1/results/{source_id}/reports/{key}",
            )
            for key, report in source.reports.items()
            if Path(report.path).is_file() and not Path(report.path).is_symlink()
        ]
        return value

    @router.get("/{source_id}/reports/{report_id}")
    def download(source_id: str, report_id: str):
        source = source_for(source_id)
        report = source.reports.get(report_id)
        if report is None:
            raise HTTPException(404, "Report not found")
        try:
            descriptor = os.open(
                report.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            )
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT:
                    raise ValueError
                body = stream.read(MAX_REPORT + 1)
                if len(body) > MAX_REPORT:
                    raise ValueError
        except (OSError, ValueError):
            raise HTTPException(404, "Report unavailable") from None
        suffix = report.path.suffix.lower()
        if suffix not in {".html", ".json", ".md", ".txt"}:
            suffix = ".download"
        return Response(
            body,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{report_id}{suffix}"',
                "Content-Security-Policy": "sandbox; default-src 'none'",
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    return router
