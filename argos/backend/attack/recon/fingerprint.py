"""Evidence-bound offline technology correlation over existing State/Evidence."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from argos.backend.attack.pentest.evidence_store import EvidenceStore
from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.store import WebStore
from argos.backend.core.mission_store import MissionStore

from .fingerprint_signals import CATALOG, RULESET, Indicator, nmap_indicators
from .network import network_report
from .store import ReconStore

MAX_HTTP = 256
MAX_NETWORK_JOBS = 64


@dataclass(frozen=True)
class EvidenceReference:
    kind: str
    id: str
    mission_id: str
    sha256: str


@dataclass(frozen=True)
class TechnologyObservation:
    asset: str
    indicator: Indicator
    evidence: EvidenceReference


def correlate(
    observations: list[TechnologyObservation], assets: set[str]
) -> list[dict]:
    groups: dict[tuple[str, str], list[TechnologyObservation]] = {}
    for observation in observations:
        groups.setdefault(
            (observation.asset, observation.indicator.technology), []
        ).append(observation)
    results = []
    for (asset, technology), group in sorted(groups.items()):
        versions = sorted({o.indicator.version for o in group if o.indicator.version})
        families = {o.indicator.source for o in group}
        receipts = {o.evidence.id for o in group}
        direct = technology == "tls" and "tls" in families
        confirmed = direct or len(families) >= 2 and len(receipts) >= 2
        conflict = len(versions) > 1 and technology != "tls"
        status = (
            "contradictory" if conflict else "confirmed" if confirmed else "probable"
        )
        version_sources = {o.evidence.id for o in group if o.indicator.version}
        evidence = {digest(asdict(o)): asdict(o) for o in group}
        results.append(
            dict(
                id=digest([asset, technology])[:24],
                asset=asset,
                technology=technology,
                category=CATALOG[technology],
                status=status,
                confidence=0.0
                if status == "contradictory"
                else 1.0
                if direct
                else 0.9
                if confirmed
                else 0.6,
                version=versions[0] if len(versions) == 1 else None,
                versions=versions,
                version_status="contradictory"
                if conflict
                else "confirmed"
                if versions and (direct or confirmed and len(version_sources) >= 2)
                else "probable"
                if versions
                else "unknown",
                evidence=[evidence[key] for key in sorted(evidence)],
            )
        )
    for asset in sorted(assets - {o.asset for o in observations}):
        results.append(
            dict(
                id=digest([asset, None])[:24],
                asset=asset,
                technology=None,
                category="unknown",
                status="unknown",
                confidence=0.0,
                version=None,
                versions=[],
                version_status="unknown",
                evidence=[],
            )
        )
    return results


def collect(database, mission_id=None, network_run_id=None, *, http_ids=None):
    if mission_id is None and network_run_id is None:
        raise ValueError("A web mission or network run is required")
    if http_ids is not None and (
        len(http_ids) > MAX_HTTP or len(set(http_ids)) != len(http_ids)
    ):
        raise ValueError("HTTP observation limit or duplicate sources")
    observations: list[TechnologyObservation] = []
    assets: set[str] = set()
    bindings: dict[tuple[str, int], set[str]] = {}
    references: dict[str, dict] = {}
    limitations = set()
    selected_http = []
    if mission_id is not None:
        with MissionStore(database) as missions:
            record = missions.get(mission_id)
            if record is None or record.web_configuration is None:
                raise ValueError("A web mission is required")
        with WebStore(database, readonly=True) as store:
            exists = store.db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='web_http_requests'"
            ).fetchone()
            rows = (
                store.db.execute(
                    "SELECT id FROM web_http_requests WHERE mission_id=? "
                    "AND state='completed' ORDER BY rowid LIMIT ?",
                    (str(mission_id), MAX_HTTP + 1),
                ).fetchall()
                if exists
                else []
            )
            ids = (
                http_ids
                if http_ids is not None
                else [row["id"] for row in rows[:MAX_HTTP]]
            )
            if len(rows) > MAX_HTTP:
                limitations.add("http_observation_limit")
            for rid in ids:
                request, row = store.private_request(UUID(rid))
                if request.mission_id != mission_id:
                    raise WebIntegrityError("Fingerprint HTTP mission differs")
                proof = store.evidence(UUID(rid))
                if proof is None or proof["state"] != "completed":
                    raise WebIntegrityError(
                        "Fingerprint requires completed HTTP evidence"
                    )
                selected_http.append(str(rid))
                asset = row["origin"]
                assets.add(asset)
                ref = EvidenceReference(
                    "http", str(rid), str(mission_id), digest(proof)
                )
                references[ref.id] = asdict(ref)
                response = proof.get("response") or {}
                bundle = response.get("technology")
                if bundle is None:
                    limitations.add("historical_http_without_indicators")
                elif bundle.get("ruleset") != RULESET:
                    raise WebIntegrityError("Unsupported fingerprint ruleset")
                else:
                    if bundle.get("limited"):
                        limitations.add("http_indicator_limit")
                    for signal in bundle["signals"]:
                        item = Indicator(**signal)
                        if (
                            item.technology not in CATALOG
                            or item.category != CATALOG[item.technology]
                        ):
                            raise WebIntegrityError("Unsupported technology indicator")
                        observations.append(TechnologyObservation(asset, item, ref))
                ticket = store.ticket(UUID(rid))
                profile = (
                    json.loads(ticket["profile_json"])
                    if ticket and ticket["profile_json"]
                    else {}
                )
                address = profile.get("target_ip")
                port = urlsplit(request.url).port or (
                    443 if request.url.startswith("https:") else 80
                )
                if address:
                    bindings.setdefault((address, port), set()).add(asset)
    if network_run_id is not None:
        run = network_report(database, network_run_id)
        if len(run["stages"]) > MAX_NETWORK_JOBS:
            raise ValueError("Network observation limit")
        if run["status"] != "completed":
            limitations.add("partial_network_run")
        with EvidenceStore(database) as store:
            for stage in run["stages"]:
                if stage["state"] != "completed":
                    continue
                proof = store.get_verified(UUID(stage["job_id"]))
                if proof is None or proof.record.observation is None:
                    raise WebIntegrityError("Missing network fingerprint evidence")
                ref = EvidenceReference(
                    "nmap",
                    stage["job_id"],
                    run["mission_id"],
                    proof.receipt.record_sha256,
                )
                references[ref.id] = asdict(ref)
                for port in proof.record.observation.ports:
                    if port.state != "open":
                        continue
                    host = f"[{port.host}]" if ":" in port.host else port.host
                    destinations = bindings.get(
                        (port.host, port.port), {f"tcp://{host}:{port.port}"}
                    )
                    for asset in destinations:
                        assets.add(asset)
                        for item in nmap_indicators(port):
                            observations.append(TechnologyObservation(asset, item, ref))
    return dict(
        identifications=correlate(observations, assets),
        sources=[references[k] for k in sorted(references)],
        http_ids=selected_http,
        limitations=sorted(limitations),
    )


def fingerprint(database, mission_id=None, network_run_id=None):
    with RuntimeLock(str(database) + ".recon"):
        result = collect(database, mission_id, network_run_id)
        value: dict = dict(
            version="fingerprint-v1",
            kind="fingerprint",
            id=str(uuid4()),
            mission_id=str(mission_id) if mission_id else None,
            network_run_id=str(network_run_id) if network_run_id else None,
            ruleset=RULESET,
            created_at=datetime.now(UTC).isoformat(),
            status="completed",
            reason="offline_analysis",
            stages=[],
            network_requests_sent=0,
            **result,
        )
        with ReconStore(database) as archive:
            archive.initialize()
            archive.save(value)
        return value


def fingerprint_report(database, run_id):
    with ReconStore(database, readonly=True) as archive:
        value = archive.get(run_id)
    if value.get("kind") != "fingerprint" or value.get("ruleset") != RULESET:
        raise ValueError("Expected a supported fingerprint run")
    current = collect(
        database,
        UUID(value["mission_id"]) if value["mission_id"] else None,
        UUID(value["network_run_id"]) if value["network_run_id"] else None,
        http_ids=value["http_ids"],
    )
    if (
        current["identifications"] != value["identifications"]
        or current["sources"] != value["sources"]
    ):
        raise WebIntegrityError("Fingerprint projection differs from source evidence")
    return value
