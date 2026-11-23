"""Offline evaluator only. Never import this module into an Argos worker."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sqlite3
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit
from uuid import UUID

from argos.backend.api.routes.results import database, details, exists
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.exploration import summary
from argos.backend.attack.web.reporting import findings_export
from argos.backend.core.config import ResultSource
from argos.backend.core.mission_store import MissionStore

# Evaluator policy, not an endpoint wordlist. Applied before mission signature.
# Socket.IO publishes challenge-solved notifications, including answer metadata.
FORBIDDEN = (
    "/api/Challenges",
    "/api/Hints",
    "/rest/challenges",
    "/rest/continue-code",
    "/rest/continue-code-findIt",
    "/rest/continue-code-fixIt",
    "/snippets",
    "/score-board",
    "/socket.io",
    "/solve/challenges",
    "/rest/chat",
    "/rest/repeat-notification",
    "/rest/web3/nftUnlocked",
    "/rest/web3/nftMintListen",
    "/metrics",
)
LIMIT = 32 * 1024 * 1024


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    if path.stat().st_size > LIMIT:
        raise ValueError("Evaluator input too large")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def write(path: Path, value: dict | str) -> None:
    """Private, exclusive output: never overwrite input databases or symlinks."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(data)


def forbidden(url: str) -> bool:
    path = (
        url.split("?", 1)[0].split("#", 1)[0]
        if url.startswith("/")
        else urlsplit(url).path
    )
    for _ in range(3):
        path = unquote(path)
    path = re.sub(r"/+", "/", path.replace("\\", "/")).casefold()
    # Dot segments and matrix parameters must not hide a protected resource.
    segments: list[str] = []
    for segment in path.split("/"):
        segment = segment.split(";", 1)[0]
        if segment == "..":
            if segments:
                segments.pop()
        elif segment and segment != ".":
            segments.append(segment)
    path = "/" + "/".join(segments)
    return any(path == p.lower() or path.startswith(p.lower() + "/") for p in FORBIDDEN)


def catalog(source: Path, environment: str, safety: str) -> dict:
    """Read upstream YAML with Juice Shop's existing parser, not a new dependency.

    No solutions/descriptions/hints are copied. Source checkout is trusted
    evaluator code; Node is never invoked with agent-selected arguments.
    """
    source = source.resolve(strict=True)
    version = json.loads((source / "package.json").read_text())["version"]
    if version not in {"20.4.0", "20.4.0-SNAPSHOT"}:
        raise ValueError("Expected Juice Shop 20.4.0 (or explicitly labelled SNAPSHOT)")
    script = """
const fs = require('node:fs');
const yaml = require(require.resolve('js-yaml', {paths: [process.cwd()]}));
const rows = yaml.load(fs.readFileSync('data/static/challenges.yml', 'utf8'));
process.stdout.write(JSON.stringify(rows.map(c => ({
  key:c.key, name:c.name, category:c.category, difficulty:c.difficulty,
  disabledEnv:c.disabledEnv || []
}))));
"""
    rows = json.loads(
        subprocess.run(
            ["node", "-e", script],
            cwd=source,
            check=True,
            capture_output=True,
            timeout=15,
        ).stdout
    )
    keys = [row["key"] for row in rows]
    if not keys or len(set(keys)) != len(keys):
        raise ValueError("Invalid official challenge catalog")
    for row in rows:
        disabled = row["disabledEnv"]
        row["available"] = (
            not disabled
            or safety == "disabled"
            or (safety == "auto" and environment not in disabled)
        )
    # Verifiable subset only: literal GET declarations, not guessed challenge URLs.
    resources = []
    server = (source / "server.ts").read_text()
    for match in re.finditer(r"app\.get\(\s*(['\"])(/[^'\"]*)\1\s*,", server):
        path = match[2]
        if any(c in path for c in ":*?{}()") or forbidden(path):
            continue
        resources.append(
            dict(
                method="GET",
                path=path,
                source="server.ts",
                line=server.count("\n", 0, match.start()) + 1,
            )
        )
    return dict(
        schema_version=1,
        version=version,
        exact_release=version == "20.4.0",
        environment=environment,
        safety=safety,
        challenges=rows,
        resources=resources,
        sources={
            p: sha(source / p)
            for p in (
                "package.json",
                "data/static/challenges.yml",
                "server.ts",
                "LICENSE",
            )
        },
        resource_scope="literal non-parameterized app.get declarations only",
    )


def snapshot(catalog_path: Path, state_db: Path, instance: str, run: str) -> dict:
    reference = load(catalog_path)
    with sqlite3.connect(
        state_db.resolve(strict=True).as_uri() + "?mode=ro", uri=True
    ) as db:
        db.execute("PRAGMA query_only=ON")
        states = dict(db.execute("SELECT key, solved FROM Challenges"))
    expected = {c["key"] for c in reference["challenges"]}
    if set(states) != expected or any(v not in (0, 1) for v in states.values()):
        raise ValueError("Official state does not match imported challenge catalog")
    return dict(
        schema_version=1,
        catalog_sha256=sha(catalog_path),
        instance_id=str(UUID(instance)),
        run_id=str(UUID(run)),
        captured_at=datetime.now(UTC).isoformat(),
        states=states,
        source="read-only official Challenges SQLite table",
    )


def official_score(
    reference: dict, before: dict | None, after: dict | None, catalog_sha: str
) -> dict:
    if (before is None) != (after is None):
        raise ValueError("Both official snapshots are required")
    if before is None or after is None:
        return dict(
            status="not_measured",
            newly_solved=None,
            reason="Paired official snapshots from a reset instance required",
        )
    for name in ("catalog_sha256", "instance_id", "run_id"):
        if before[name] != after[name]:
            raise ValueError("Official snapshots belong to different runs")
    if before["catalog_sha256"] != catalog_sha:
        raise ValueError("Official snapshots belong to another catalog")
    start, end = (datetime.fromisoformat(v["captured_at"]) for v in (before, after))
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise ValueError("Official snapshots are not ordered UTC instants")
    keys = {c["key"] for c in reference["challenges"]}
    if any(
        set(v["states"]) != keys
        or any(type(n) is not int or n not in (0, 1) for n in v["states"].values())
        for v in (before, after)
    ):
        raise ValueError("Incomplete official snapshots")
    if any(before["states"].values()):
        return dict(
            status="invalid_baseline",
            newly_solved=None,
            reason="Instance was not reset: already solved challenges",
        )
    available = {c["key"] for c in reference["challenges"] if c["available"]}
    solved = sorted(k for k in available if after["states"][k])
    return dict(
        status="official_state_delta",
        newly_solved=len(solved),
        keys=solved,
        instance_id=before["instance_id"],
        run_id=before["run_id"],
        interval=[before["captured_at"], after["captured_at"]],
        attribution="State change only; isolated exclusive run required",
    )


def evaluate(
    reference: dict,
    observation: dict,
    detections: list[dict],
    score: dict,
    policy_applied: bool,
) -> tuple[dict, list[dict]]:
    audit = [
        dict(
            request_id=r["id"],
            path=urlsplit(r["url"]).path,
            recorded_at=r["recorded_at"],
            forbidden=forbidden(r["url"]),
            evidence=r["evidence_sha256"],
        )
        for r in observation["requests"]
    ]
    violations = [r for r in audit if r["forbidden"]]
    verified = [r for r in observation["requests"] if r["verification"] == "verified"]
    observed = {
        urlsplit(r["url"]).path
        for r in verified
        if r["method"] == "GET"
        and r["http_status"] is not None
        and r["classification"] not in {"spa_generic", "probe", "unverified"}
        and not forbidden(r["url"])
    }
    expected = {r["path"] for r in reference["resources"]}
    return dict(
        schema_version=1,
        generated_at=datetime.now(UTC).isoformat(),
        mission_id=observation["id"],
        targets=observation["targets"],
        version=reference["version"],
        exact_release=reference["exact_release"],
        challenges=dict(
            imported=len(reference["challenges"]),
            available=sum(c["available"] for c in reference["challenges"]),
            availability_basis="source disabledEnv + declared environment/safety",
            environment=reference.get("environment"),
            safety=reference.get("safety"),
        ),
        reconnaissance=dict(
            requests=len(audit),
            verified_receipts=len(verified),
            classifications=dict(Counter(r["classification"] for r in verified)),
            expected_resources=len(expected),
            matched=sorted(expected & observed),
            missed=sorted(expected - observed),
            observed_unmapped=sorted(observed - expected),
            matched_responses=[
                dict(
                    path=urlsplit(r["url"]).path,
                    status=r["http_status"],
                    receipt_sha256=r["evidence_sha256"],
                )
                for r in verified
                if urlsplit(r["url"]).path in expected & observed
            ],
            static_references=sum(
                r["reason"] == "static_reference" for r in observation["routes"]
            ),
            provenance=dict(
                Counter(
                    p["kind"] for r in observation["routes"] for p in r["provenance"]
                )
            ),
            reference_scope=reference["resource_scope"],
            note=(
                "HTTP response is not a verified vulnerability; "
                "unmapped is not false positive"
            ),
        ),
        detections=dict(
            confirmed=sum(f["status"] == "confirmed" for f in detections),
            persisted_findings=len(detections),
            official_challenge_correspondence="not_established",
        ),
        official_challenges=score,
        isolation=dict(
            status="violated" if violations else "not_qualified",
            policy_in_mission_configuration=policy_applied,
            violations=violations,
            access_log="access.jsonl",
            note=(
                "Worker mounts exclude evaluator files; host/LLM isolation "
                "and complete ingress logs not attested"
            ),
        ),
        limitations=[
            "No offensive test; no LLM statement accepted as evidence.",
            "Source GET subset is not a full inventory or challenge mapping.",
            "Public bundles may contain hints; no response-body filtering.",
            "Blocking Socket.IO/chatbot/hints affects training UI features.",
            "Historical receipts are not complete ingress/filesystem logs.",
            "Zero solved flags do not attest a full application/data reset.",
        ],
    ), audit


def render(report: dict) -> str:
    # Escaped, offline, no scripts/assets or untrusted clickable links.
    sections = "".join(
        f"<h2>{html.escape(k)}</h2><pre>{html.escape(json.dumps(v, indent=2))}</pre>"
        for k, v in report.items()
    )
    return (
        '<!doctype html><html lang="fr"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>Argos — benchmark Juice Shop</title><style>"
        "body{max-width:960px;margin:2rem auto;padding:1rem;background:#081421;"
        "color:#d7e8ed;font:15px system-ui}h1,h2{color:#62dbe9}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;"
        "padding:1rem;background:#101f30;border-radius:8px}</style>"
        "<h1>Benchmark Juice Shop — évaluation hors ligne</h1>" + sections + "</html>"
    )


def ingress_audit(path: Path) -> dict:
    """Read only the evaluator guard journal, never trust it as a success oracle."""
    if path.stat().st_size > LIMIT:
        raise ValueError("Ingress journal too large")
    events = [json.loads(line) for line in path.read_text().splitlines()]
    violations = []
    for event in events:
        if event["action"] not in {"blocked", "forwarded"}:
            raise ValueError("Invalid guard action")
        datetime.fromisoformat(event["at"])
        if forbidden(event["path"]):
            violations.append({k: event[k] for k in ("at", "path", "action")})
    return dict(
        events=len(events),
        attempts=violations,
        exposed=sum(v["action"] == "forwarded" for v in violations),
        sha256=sha(path),
        attested=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    imp = commands.add_parser("import")
    imp.add_argument("--source", type=Path, required=True)
    imp.add_argument(
        "--environment", choices=["Linux", "Docker", "Heroku", "Windows"], required=True
    )
    imp.add_argument("--safety", choices=["auto", "enabled", "disabled"], required=True)
    imp.add_argument("--out", type=Path, required=True)
    snap = commands.add_parser("snapshot")
    for name in ("catalog", "state-db", "out"):
        snap.add_argument("--" + name, type=Path, required=True)
    snap.add_argument("--instance-id", required=True)
    snap.add_argument("--run-id", required=True)
    policy = commands.add_parser("protect-config")
    policy.add_argument("--config", type=Path, required=True)
    policy.add_argument("--out", type=Path, required=True)
    ev = commands.add_parser("evaluate")
    for name in ("catalog", "database", "out"):
        ev.add_argument("--" + name, type=Path, required=True)
    ev.add_argument("--mission", type=UUID, required=True)
    ev.add_argument("--before", type=Path)
    ev.add_argument("--after", type=Path)
    ev.add_argument("--access-log", type=Path)
    args = parser.parse_args()
    if args.command == "import":
        write(args.out, catalog(args.source, args.environment, args.safety))
    elif args.command == "snapshot":
        write(
            args.out,
            snapshot(args.catalog, args.state_db, args.instance_id, args.run_id),
        )
    elif args.command == "protect-config":
        value = load(args.config)
        value["scope"]["excluded_paths"] = sorted(
            set(value["scope"].get("excluded_paths", []) + list(FORBIDDEN))
        )
        write(args.out, json.loads(WebMissionConfig.from_dict(value).to_json()))
    else:
        reference = load(args.catalog)
        source = ResultSource(
            label="Evaluator", database=args.database.resolve(strict=True)
        )
        with database(source) as store:
            observation = details(store, source, args.mission)
            detections = []
            runs = (
                store.db.execute(
                    "SELECT id FROM web_discovery_runs WHERE mission_id=?",
                    (str(args.mission),),
                ).fetchall()
                if exists(store.db, "web_discovery_runs")
                else []
            )
            for row in runs:
                detections.extend(
                    findings_export(summary(store, UUID(row["id"]), details=True))[
                        "findings"
                    ]
                )
            record = MissionStore("", connection=store.db).get(args.mission)
            assert record is not None and record.web_configuration is not None
            config = json.loads(record.web_configuration)
            paths = config["scope"].get("excluded_paths", [])
            protected = all(
                any(p == x or p.startswith(x.rstrip("/") + "/") for x in paths)
                for p in FORBIDDEN
            )
        score = official_score(
            reference,
            load(args.before) if args.before else None,
            load(args.after) if args.after else None,
            sha(args.catalog),
        )
        if args.before and args.after:
            baseline, final = load(args.before), load(args.after)
            if baseline["run_id"] != str(args.mission):
                raise ValueError("Official snapshot run-id must equal Argos mission ID")
            start, end = (
                datetime.fromisoformat(v["captured_at"]) for v in (baseline, final)
            )
            if any(
                not start <= datetime.fromisoformat(r["recorded_at"]) <= end
                for r in observation["requests"]
                if r["recorded_at"]
            ):
                raise ValueError("Official snapshots do not bracket mission receipts")
        score["attribution_qualified"] = False
        report, audit = evaluate(reference, observation, detections, score, protected)
        if args.access_log:
            report["isolation"]["ingress"] = ingress_audit(args.access_log)
            if report["isolation"]["ingress"]["exposed"]:
                report["isolation"]["status"] = "violated"
        report["input_sha256"] = dict(
            catalog=sha(args.catalog),
            projected_observations=hashlib.sha256(
                json.dumps(observation, sort_keys=True).encode()
            ).hexdigest(),
        )
        write(args.out / "benchmark.json", report)
        write(args.out / "benchmark.html", render(report))
        write(args.out / "access.jsonl", "".join(json.dumps(r) + "\n" for r in audit))
        print(
            json.dumps(
                dict(
                    report=str(args.out.resolve()),
                    isolation=report["isolation"]["status"],
                    official_score=score["status"],
                )
            )
        )


if __name__ == "__main__":
    main()
