"""Diagnostic reproductible sur les archives Recon, sans exécution de mission."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections import Counter
from contextlib import closing
from pathlib import Path
from time import perf_counter
from urllib.parse import urlsplit
from uuid import UUID

from argos.backend.attack.recon.application_mapping import application_report
from argos.backend.attack.recon.context_execution import context_report
from argos.backend.attack.recon.context_plan import plan_report
from argos.backend.attack.recon.fingerprint import fingerprint_report
from argos.backend.attack.recon.network import network_report
from argos.backend.attack.web.evidence_index import evidence_index
from argos.backend.attack.web.exploration import summary
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.report_coverage import coverage_export
from argos.backend.attack.web.reporting import findings_export, render_markdown
from argos.backend.attack.web.static_discovery import _TOKEN, javascript_references
from argos.backend.attack.web.store import WebStore
from scripts.recon_qualification import transactions

CATALOG = Path(__file__).with_name("corpus.json")
LABS = ("juice", "crapi", "dvwa")
BUNDLES = {
    "juice": ("juice-main.js", "juice-vendor.js"),
    "crapi": ("crapi-vendor.js",),
    "dvwa": (),
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_archive(root: Path, pin: str) -> dict:
    manifest = root / "manifest.json"
    if sha256(manifest) != pin:
        raise ValueError(f"Manifest differs: {manifest}")
    entries = read_json(manifest)
    for name, expected in entries.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or sha256(path) != expected:
            raise ValueError(f"Archive entry differs: {name}")
    return entries


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + ("?" + parts.query if parts.query else "")


def raw_replay(body: bytes, url: str, paths: set[str]) -> dict:
    references, limited = javascript_references(url, body)
    text = body.decode("utf-8", errors="replace")
    # A limited replay only makes claims about the archived bytes.
    tokens = [(m.start(), m.end()) for m in _TOKEN.finditer(text)]
    return {
        path: {
            "literal_hits": text.count(path),
            "oversized_tokens": sorted(
                end - start - 2
                for start, end in tokens
                if end - start - 2 > 8192 and path in text[start:end]
            ),
            "normalized": [
                r["relation"] for r in references if path_of(r["url"]) == path
            ],
            "parser_limited": limited,
        }
        for path in sorted(paths)
    }


def audit_trial(root: Path, lab: str, suffix: str, expected: set[str]) -> dict:
    directory = root / f"{lab}-contextual-{suffix}"
    trial = read_json(directory / "trial.json")
    phases = trial["phases"]
    database = directory / "missions.sqlite"
    timings = {}

    def timed(label, reader, *args):
        started = perf_counter()
        result = reader(*args)
        timings[label] = round(perf_counter() - started, 6)
        return result

    def report(phase, reader):
        return timed(phase, reader, database, UUID(phases[phase]["id"]))

    network = report("network", network_report)
    enumeration = report("enumeration", context_report)
    fingerprint = report("fingerprint", fingerprint_report)
    mapping = report("final_map", application_report)
    initial_map = report("initial_map", application_report)
    plan = timed("plan", plan_report, database, UUID(enumeration["plan_id"]))
    rows = timed("http_receipts", transactions, database, UUID(trial["mission_id"]))
    if rows != trial["transactions"] or any(
        trial[key] != value
        for key, value in (
            ("enumeration", enumeration),
            ("fingerprint", fingerprint),
            ("mapping", mapping),
        )
    ):
        raise ValueError(f"Trial differs from product reports: {directory}")

    with closing(
        sqlite3.connect(database.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        frontier = Frontier(connection)
        captures = [
            capture
            for row in rows
            if (capture := frontier.capture(UUID(row["id"]))) is not None
        ]
        nav_count = connection.execute(
            "SELECT count(*) FROM web_browser_navigations"
        ).fetchone()[0]
    origin = trial["url"].rstrip("/")

    def target_path(url: str) -> str | None:
        return path_of(url) if url.startswith(origin + "/") else None

    with WebStore(database, readonly=True) as store:
        web = timed(
            "web_summary",
            lambda: summary(store, UUID(phases["collection"]["id"]), details=True),
        )
    index = timed("w6_evidence_index", evidence_index, web)
    timed("w6_coverage", coverage_export, web)
    timed("w6_findings", findings_export, web)
    timed("w6_markdown", render_markdown, web)
    w6_ids = {row["request_id"] for row in index["receipts"]}
    normalized = {
        target_path(r["url"]) for c in captures for r in c.get("references", [])
    }
    by_id = {row["id"]: row for row in rows}

    def reference_responses(requests) -> set[str]:
        return expected.intersection(
            target_path(row["url"]) for row in requests if row["status"] is not None
        )

    observed = reference_responses(rows)
    candidates = {target_path(c["url"]): c for c in plan["selection"]["candidates"]}
    maps = {
        label: {n["key"]: n for n in graph["nodes"] if n["kind"] == "resource"}
        for label, graph in (("initial", initial_map), ("final", mapping))
    }
    generic = []
    for item in enumeration["ledger"]:
        if item["outcome"] != "generic_response_suspected":
            continue
        for proof in item["evidence"]:
            row = by_id[proof["id"]]
            path = path_of(row["url"])
            node = maps["final"].get(row["url"])
            generic.append(
                dict(
                    path=path,
                    ledger_state=item["outcome"],
                    status=row["status"],
                    receipt=proof,
                    map_state=node["state"] if node else None,
                    map_node=node["id"] if node else None,
                    in_w6_index=row["id"] in w6_ids,
                )
            )

    enum_ids = set(enumeration["coverage"]["all_request_ids"])
    seen = reference_responses(row for row in rows if row["id"] not in enum_ids)
    collection_responses = len(seen)
    stages = []
    for stage in enumeration["stages"]:
        requests = [by_id[r["request_id"]] for r in stage["requests"]]
        paths = reference_responses(requests)
        stages.append(
            dict(
                tool=stage["tool"],
                state=stage["state"],
                reason=stage.get("reason"),
                duration_seconds=None,
                tickets=sum(r["ticket"] for r in requests),
                first_reference_responses=sorted(paths - seen),
            )
        )
        seen.update(paths)
    missed = expected - observed
    omissions = [
        dict(
            path=path,
            normalized=path in normalized,
            plan_decision=candidates.get(path, {}).get("decision"),
            candidate_id=candidates.get(path, {}).get("id"),
            request_ids=[r["id"] for r in rows if target_path(r["url"]) == path],
            initial_map=origin + path in maps["initial"],
            final_map=origin + path in maps["final"],
        )
        for path in sorted(missed)
    ]
    return dict(
        archived_phases=phases,
        archived_cost=dict(
            duration_seconds=trial["duration_seconds"],
            child_cpu_seconds=trial["child_cpu_seconds"],
            child_maxrss_kib_process_highwater=trial[
                "child_maxrss_kib_process_highwater"
            ],
        ),
        offline_reader_seconds=timings,
        network=dict(
            coverage=network["coverage"],
            nmap_packet_count=trial["nmap_packet_count"],
        ),
        http=dict(
            examined=sorted(observed),
            tickets=sum(r["ticket"] for r in rows),
            retained_response_bytes=trial["retained_response_bytes"],
            evidence_bytes=trial["evidence_bytes"],
            response_statuses=dict(Counter(str(r["status"]) for r in rows)),
            control_tickets=enumeration["coverage"]["control_http_requests"],
            repeated_gets=sum(
                count - 1
                for count in Counter(r["url"] for r in rows if r["ticket"]).values()
            ),
            collection_reference_responses=collection_responses,
            stages=stages,
        ),
        w6=dict(coverage_export_generated=True, indexed_receipts=len(w6_ids)),
        fingerprinting=fingerprint["identifications"],
        dom=dict(navigations=nav_count, coverage=None),
        api=dict(
            projected_operations=mapping["metrics"]["node_kinds"].get(
                "http_operation", 0
            ),
            coverage=None,
        ),
        omissions=omissions,
        generic=generic,
    )


def audit(root: Path) -> dict:
    corpus = read_json(CATALOG)
    baseline = read_json(CATALOG.with_name("baseline.json"))
    manifests = {
        name: verify_archive(root / name, pin)
        for name, pin in corpus["archives"].items()
    }
    compose = root / "m271" / "compose.lock.json"
    if (
        sha256(compose) != corpus["historical_compose_sha256"]
        or {
            name: service["image"]
            for name, service in read_json(compose)["services"].items()
        }
        != corpus["images"]
    ):
        raise ValueError("Historical composition differs")
    trials = {}
    for lab in LABS:
        expected = {r["path"] for r in corpus["historical"][lab]["resources"]}
        old = audit_trial(root / "m27", lab, "r3", expected)
        current = audit_trial(root / "m271", lab, "r1", expected)
        paths = {r["path"] for r in current["omissions"]}
        raw = {}
        raw_measurements = {}
        for name in BUNDLES[lab]:
            body = (root / "m271" / name).read_bytes()
            started = perf_counter()
            raw[name] = raw_replay(body, f"http://fixture.invalid/{name}", paths)
            raw_measurements[name] = dict(
                bytes=len(body), diagnostic_seconds=round(perf_counter() - started, 6)
            )
        frozen = baseline[lab]
        misses = frozen["omissions"]
        if any(
            trial["http"]["examined"] != frozen["examined"]
            or {r["path"] for r in trial["omissions"]} != set(misses)
            for trial in (old, current)
        ):
            raise ValueError(f"Historical HTTP baseline differs: {lab}")
        for omission in current["omissions"]:
            path = omission["path"]
            reason = misses[path]
            if (
                omission["normalized"]
                or omission["request_ids"]
                or omission["initial_map"]
                or omission["final_map"]
                or omission["plan_decision"]
                != ("candidate_budget" if reason == "candidate_budget" else None)
                or (
                    reason == "oversized_js_token"
                    and not any(
                        r[path]["oversized_tokens"] and not r[path]["normalized"]
                        for r in raw.values()
                    )
                )
            ):
                raise ValueError(f"Historical omission differs: {lab} {path}")
            omission["diagnosis"] = reason
        if (
            len(current["generic"]) != frozen["generic_observed_map"]
            or any(item["map_state"] != "observed" for item in current["generic"])
            or sum(item["in_w6_index"] for item in current["generic"])
            != frozen["generic_in_w6_index"]
        ):
            raise ValueError(f"Historical generic projection differs: {lab}")
        trials[lab] = dict(
            m27=old,
            m271=current,
            available_raw_replays=raw,
            raw_measurements=raw_measurements,
        )
    return dict(
        schema=1,
        archive_entries={name: len(entries) for name, entries in manifests.items()},
        trials=trials,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.archives), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
