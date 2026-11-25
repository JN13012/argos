"""A consistent offline view of archived Argos mission evidence."""

import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from math import isfinite
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from uuid import UUID

from argos.backend.attack.recon.application_mapping import application_report
from argos.backend.attack.recon.context_execution import context_report
from argos.backend.attack.recon.fingerprint import fingerprint_report
from argos.backend.attack.recon.mapping_signals import location
from argos.backend.attack.recon.network import network_report
from argos.backend.attack.web.browser_config import WebBrowserConfig
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.execution_config import WebExecutionConfig
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.receipts import WebIntegrityError, canonical, digest
from argos.backend.attack.web.store import WebStore
from argos.backend.core.mission_store import MissionStore

VERSION = "mission-state-snapshot-v1"
_READERS = {
    "application_map": application_report,
    "context_run": context_report,
    "fingerprint": fingerprint_report,
    "network": network_report,
}


def mission_snapshot(database: str | Path, mission_id: UUID) -> dict:
    """Validate archived projections against one point-in-time SQLite copy."""
    uri = Path(database).resolve().as_uri() + "?mode=ro"
    deadline = monotonic() + 10

    def bound_backup(status: int, remaining: int, total: int) -> None:
        if status in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            if monotonic() >= deadline:
                raise sqlite3.OperationalError("Mission archive is busy")

    # Some legacy readers initialize tables on open. Only the private copy
    # is writable. Do not open any runtime, grant verifier, or transport.
    with TemporaryDirectory(prefix="argos-mission-review-") as directory:
        copy = Path(directory) / "mission.sqlite"
        with (
            closing(sqlite3.connect(uri, uri=True)) as source,
            closing(sqlite3.connect(copy)) as destination,
        ):
            source.execute("BEGIN")
            source.execute("PRAGMA schema_version").fetchone()
            source.backup(destination, pages=256, progress=bound_backup)
        with WebStore(copy, readonly=True) as store:
            snapshot = _read_snapshot(store, copy, mission_id)
    return {"snapshot": snapshot, "sha256": digest(snapshot)}


def _read_snapshot(store: WebStore, database: Path, mission_id: UUID) -> dict:
    tables = {
        row[0]
        for row in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    with MissionStore(database, connection=store.db) as missions:
        record = missions.get(mission_id)
    if record is None:
        raise ValueError("Unknown mission")

    configuration = record.web_configuration
    config = WebMissionConfig.from_json(configuration) if configuration else None
    config_sha = digest(json.loads(configuration)) if configuration else None
    http, http_budget = _http_archive(store, tables, mission_id, config, config_sha)
    projections, omitted = _recon_archive(store, database, tables, mission_id)
    contradictions = [
        {"run_id": item["id"], "observation_id": claim["id"]}
        for item in projections
        for claim in (
            item.get("identifications", [])
            + item.get("nodes", [])
            + item.get("relations", [])
        )
        if "contradictory"
        in (claim.get("state"), claim.get("status"), claim.get("version_status"))
    ]
    return {
        "version": VERSION,
        "mission": {
            "id": str(mission_id),
            "state_at_capture": record.mission.state.value,
            "expires_at": record.mission.expires_at.isoformat(),
            "configuration_sha256": config_sha,
        },
        "http": http,
        "projections": projections,
        "contradictions": contradictions,
        "budgets": {"http": http_budget},
        "coverage": {
            "exhaustive": False,
            "http_archive_present": "web_http_requests" in tables,
            "omitted_recon_records_by_kind": omitted,
            "limitations": [
                "historical_observations_only",
                "archived_recon_projections_only",
                "contradictions_reported_within_each_projection",
                "capture_and_browser_storage_excluded_from_http_evidence_accounting",
            ],
        },
    }


def _http_archive(
    store: WebStore,
    tables: set[str],
    mission_id: UUID,
    config: WebMissionConfig | None,
    config_sha: str | None,
) -> tuple[list[dict], dict | None]:
    requests = []
    reservations = receipt_and_reservation_bytes = 0
    if "web_http_requests" in tables:
        rows = store.db.execute(
            "SELECT id FROM web_http_requests WHERE mission_id=? ORDER BY id",
            (str(mission_id),),
        )
        for (identifier,) in rows:
            rid = UUID(identifier)
            request, row = store.private_request(rid)
            receipt = store.evidence(rid)
            if (
                request.mission_id != mission_id
                or row["configuration_sha256"] != config_sha
                or receipt is not None
                and (
                    receipt["mission_id"] != str(mission_id)
                    or receipt["request_id"] != identifier
                )
            ):
                raise WebIntegrityError("HTTP archive mission or configuration differs")
            ticket = store.ticket(rid)
            if ticket is not None:
                reservations += 1
                receipt_and_reservation_bytes += (
                    ticket["used_bytes"] if receipt is not None else ticket["capacity"]
                )
            elif receipt is not None:
                receipt_and_reservation_bytes += len(canonical(receipt).encode())
            route = location(request.url, request.url)
            requests.append(
                {
                    "request_id": identifier,
                    "route": route["url"] if route else None,
                    "method": request.method,
                    "state": row["state"],
                    "error": row["error"],
                    "evidence_sha256": row["evidence_sha256"],
                    "receipt": receipt,
                }
            )
    if config is None:
        return requests, None

    clock = None
    if "web_http_sessions" in tables:
        session = store.db.execute(
            "SELECT configuration_sha256,started,last_clock FROM web_http_sessions "
            "WHERE mission_id=?",
            (str(mission_id),),
        ).fetchone()
        if session is not None:
            sha, started, last_clock = session
            elapsed = last_clock - started
            if sha != config_sha or not isfinite(elapsed * 1000) or elapsed < 0:
                raise WebIntegrityError("HTTP archive clock or configuration differs")
            clock = int(elapsed * 1000)
    navigations = NavigationStore(store)
    navigation_usage = (
        navigations.usage(mission_id) if navigations.available() else None
    )
    return requests, {
        "configuration_limits": asdict(config.limits),
        "configured_evidence_bytes": (
            config.execution.evidence_bytes
            if isinstance(config, WebExecutionConfig)
            else None
        ),
        "configured_browser_limits": (
            asdict(config.browser) if isinstance(config, WebBrowserConfig) else None
        ),
        "archived_request_tickets": (
            reservations if "web_http_requests" in tables else None
        ),
        "http_ticket_and_receipt_bytes": (
            receipt_and_reservation_bytes if "web_http_requests" in tables else None
        ),
        "archived_navigation_tickets": (
            navigation_usage.navigations_used if navigation_usage is not None else None
        ),
        "elapsed_ms_at_last_persisted_clock": clock,
    }


def _recon_archive(
    store: WebStore,
    database: Path,
    tables: set[str],
    mission_id: UUID,
) -> tuple[list[dict], dict[str, int]]:
    if "recon_runs" not in tables:
        return [], {}
    key = str(mission_id)
    rows = store.db.execute(
        """
        WITH own AS (
            SELECT id, json_extract(payload, '$.kind') AS kind
            FROM recon_runs WHERE json_extract(payload, '$.mission_id')=?
        )
        SELECT id, kind FROM own
        UNION ALL
        SELECT id, json_extract(payload, '$.kind') FROM recon_runs
        WHERE json_extract(payload, '$.mission_id') IS NULL
          AND json_extract(payload, '$.kind') IN ('application_map', 'fingerprint')
          AND json_extract(payload, '$.network_run_id') IN (
              SELECT id FROM own WHERE kind='network'
          )
        ORDER BY id
        """,
        (key,),
    ).fetchall()
    reports = {}
    omitted: dict[str, int] = {}
    network_links: set[str] = set()
    owned_network_runs = {identifier for identifier, kind in rows if kind == "network"}
    for identifier, kind in rows:
        if kind not in _READERS:
            kind = (
                kind
                if kind in {"context_plan", "application_document", "pipeline"}
                else "other"
            )
            omitted[kind] = omitted.get(kind, 0) + 1
            continue
        report = _READERS[kind](database, UUID(identifier))
        network_run_id = report.get("network_run_id")
        if report["mission_id"] != key and not (
            report["mission_id"] is None and network_run_id in owned_network_runs
        ):
            raise WebIntegrityError("Recon archive mission differs")
        reports[identifier] = report
        if kind in {"fingerprint", "application_map"} and network_run_id:
            network_links.add(network_run_id)
    for identifier in sorted(network_links - reports.keys()):
        reports[identifier] = network_report(database, UUID(identifier))
    return [_project(reports[key]) for key in sorted(reports)], omitted


def _project(report: dict) -> dict:
    kind = report["kind"]
    fields = {
        "network": ("coverage", "budgets"),
        "fingerprint": ("identifications", "sources", "network_run_id"),
        "application_map": (
            "nodes",
            "relations",
            "sources",
            "coverage",
            "network_run_id",
        ),
        "context_run": ("coverage", "ledger", "stop_reason"),
    }
    item = {
        key: report[key]
        for key in ("id", "kind", "version", "mission_id", "status", "reason")
    }
    item["created_at"] = report.get("created_at")
    item["finished_at"] = report.get("finished_at")
    item["ruleset"] = report.get("ruleset")
    item["archive_sha256"] = digest(report)
    item["limitations"] = report.get("limitations", [])
    item.update({key: report.get(key) for key in fields[kind]})
    if kind == "network":
        item["observations"] = []
        for stage in report["stages"]:
            if "observation" in stage and not stage.get("evidence_sha256"):
                raise WebIntegrityError("Network observation has no receipt")
            if stage.get("evidence_sha256"):
                item["observations"].append(
                    {
                        "job_id": stage["job_id"],
                        "evidence_sha256": stage["evidence_sha256"],
                        "observation": stage.get("observation"),
                    }
                )
    if kind == "context_run":
        item["budgets"] = {
            key: report.get(key) for key in ("admissions", "effective_request_budget")
        }
    return item
