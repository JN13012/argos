"""Frozen archive qualification against already installed loopback Ollama models."""

import argparse
import asyncio
import json
import os
import platform
import resource
import shutil
import sqlite3
import subprocess
import sys
from contextlib import ExitStack, redirect_stdout
from io import StringIO
from pathlib import Path
from threading import Event, Thread
from time import perf_counter
from uuid import UUID

import httpx
from argos.backend.attack.review.analysis import _request
from argos.backend.attack.review.context import review_snapshot
from argos.backend.attack.review.context_v2 import (
    CollectionReader,
    ReviewContextV2,
    _archived,
)
from argos.backend.attack.review.memory import MemoryEngine
from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.attack.review.snapshot import mission_snapshot
from argos.backend.attack.review.workflow import (
    analyze_workflow,
    create_workflow,
    read_workflow,
)
from argos.backend.attack.review.workflow_v2 import analyze_workflow_v2
from argos.backend.attack.web.cli import verify_report
from argos.backend.attack.web.evidence_index import evidence_index
from argos.backend.attack.web.exploration import summary
from argos.backend.attack.web.report_coverage import coverage_export
from argos.backend.attack.web.reporting import findings_export, render_markdown
from argos.backend.attack.web.store import WebStore
from argos.backend.consultation.analyst import _refs
from argos.backend.consultation.context import Budget, Component, fingerprint
from argos.backend.knowledge import Collection, CollectionKind, SQLiteKnowledgeRetriever
from argos.backend.knowledge.embeddings import QWEN, OllamaEmbeddingProvider
from argos.backend.knowledge.router import RetrievalMode, RetrievalRouter
from argos.backend.knowledge.storage import CollectionDatabase
from argos.backend.knowledge.vector_index import build
from argos.backend.knowledge.vector_retrieval import NumPyKnowledgeRetriever
from benchmarks.rag_eval.archives import digest, inventory, mission_id
from benchmarks.rag_eval.resources import stop_processes
from benchmarks.rag_eval.run import DIGEST, save, store_notes
from benchmarks.retrieval.consultation_probe import api, launch, wait, wait_empty

from .measure import observe, summarize
from .reference import EXPECTED_DOCS, NOTES, PROTOCOL, freeze, identifiers, score_facts


def timed(stages: dict, key: str, operation, *args, **kwargs):
    started = perf_counter()
    try:
        return operation(*args, **kwargs)
    finally:
        stages[key] = (perf_counter() - started) * 1000


def exports(database: Path, run: UUID, out: Path, stages: dict) -> bool:
    with WebStore(database, readonly=True) as store:
        store.db.execute("BEGIN")
        report = summary(store, run, details=True)
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    paths = {}
    for name, export in (
        ("coverage", coverage_export),
        ("findings", findings_export),
        ("index", evidence_index),
    ):
        path = out / (name + ".json")
        save(path, export(report))
        paths[name] = str(path)
    with redirect_stdout(StringIO()):
        return (
            timed(
                stages,
                "w6_verify",
                verify_report,
                argparse.Namespace(run_id=run, **paths),
                database,
            )
            == 0
        )


def receipt_row(row: dict) -> dict:
    return {"source": row["citation"].get("observation", {}), **json.loads(row["text"])}


def document_id(citation: dict) -> str | None:
    ref = citation.get("reference", {})
    return ref.get("document", {}).get("document_id")


class RecordedRouter(RetrievalRouter):
    """Record retrieved IDs before assembly without changing the ranking."""

    def __init__(self, sql, dense):
        super().__init__(sql, dense)
        self.ids: list[str] = []

    def search(self, *args, **kwargs):
        result = super().search(*args, **kwargs)
        self.ids.extend(hit.document.document_id for hit in result.passages)
        return result


class RecordedSelector:
    """Collect the model's selection before the product renders it."""

    def __init__(self, delegate: OllamaSelector):
        self.delegate = delegate
        self.data: dict = {}
        self.selected: list[int] = []

    def size(self, data):
        return self.delegate.size(data)

    async def identify(self):
        return await self.delegate.identify()

    async def select(self, data, budget, model):
        selection = await self.delegate.select(data, budget, model)
        self.data = json.loads(data)
        self.selected = _refs(selection.content, len(self.data["items"]))
        return selection


def scoring_v2(
    result: dict, selector: RecordedSelector, router: RecordedRouter | None
) -> dict:
    sent = result["consultation"]
    attempt = next(e["data"] for e in result["events"] if "pins" in e["data"])
    pins = [json.loads(row["pin"]) for row in attempt["units"]]
    available = {}
    for packet, pin in zip(selector.data["items"], pins, strict=True):
        source = pin.get("observation", {})
        if source.get("kind") == "http_receipt":
            available[packet["id"]] = {
                "source": source,
                "status": json.loads(packet["text"])["status"],
            }
    claims = [
        receipt_row(row) for row in sent["claims"] if "observation" in row["citation"]
    ]
    expected_text = {note.id: note.text for note in NOTES}
    docs = set()
    invalid_documents = 0
    for row in sent["claims"]:
        doc = document_id(row["citation"])
        if doc is not None:
            if row["text"] and expected_text.get(doc, "").startswith(row["text"]):
                docs.add(doc)
            else:
                invalid_documents += 1
    declared_contradictions = {
        doc for row in sent["contradictions"] if (doc := document_id(row["citation"]))
    }
    critical_units = {
        (
            fingerprint(
                {
                    key: value
                    for key, value in row["citation"].items()
                    if key != "memory_id"
                }
            ),
            row["text"],
        )
        for row in sent["contradictions"] + sent["uncertainties"]
    }
    expected_units = [
        _archived(row, Component.ARCHIVE) for row in result["critical_items"]
    ]
    critical_shown = sum(
        (fingerprint(json.loads(unit.pin)), unit.text) in critical_units
        for unit in expected_units
    )
    return {
        "available": list(available.values()),
        "selected": [available[ref] for ref in selector.selected if ref in available],
        "restituted": claims,
        "doc_available": {doc for pin in pins if (doc := document_id(pin))},
        "doc_returned": docs,
        "doc_retrieved": set(router.ids if router else []),
        "obsolete_returned": int("retired-policy" in docs | declared_contradictions),
        "invalid_documents": invalid_documents,
        "documentary_conflict": "conflicting-policy" in declared_contradictions,
        "memory_units": sum(row["component"] == "memory" for row in attempt["units"]),
        "timings": sent["timings_ms"],
        "usage": sent["usage"],
        "critical_shown": critical_shown,
        "abstention": sent["abstention"],
    }


def score_trial(lab: str, focus: dict, reference: dict) -> dict:
    relevant = EXPECTED_DOCS[lab]
    return {
        **{
            stage: score_facts(reference, focus[stage])
            for stage in ("available", "selected", "restituted")
        },
        "documents": {
            "retrieved_relevant": len(focus["doc_retrieved"] & relevant),
            "available_relevant": len(focus["doc_available"] & relevant),
            "returned_relevant": len(focus["doc_returned"] & relevant),
            "returned_irrelevant": len(focus["doc_returned"] - relevant),
            "returned_obsolete": focus.get("obsolete_returned", 0),
            "returned_invalid_text": focus.get("invalid_documents", 0),
        },
        "memory_units": focus.get("memory_units", 0),
        "documentary_conflict": focus.get("documentary_conflict", False),
    }


def session(database, mission, arm, args, collection, embedding, dense):
    router = None
    if arm in "DEF":
        sql = SQLiteKnowledgeRetriever(collection, allowed_collections={collection})
        router = RecordedRouter(sql, dense if arm in "EF" else None)
    readers = (
        (
            CollectionReader(
                collection, sql, router, embedding.space if arm in "EF" else None
            ),
        )
        if router is not None
        else ()
    )
    memory = MemoryEngine(args.memory, mission) if arm == "F" else None
    return ReviewContextV2(
        database=database,
        mission_id=mission,
        memory=memory,
        readers=readers,
    ), router


def trial(args, frozen, lab, arm, regime, output, collection, embedding, dense) -> dict:
    started = perf_counter()
    before_cpu = resource.getrusage(resource.RUSAGE_SELF)
    output.mkdir(mode=0o700)
    stages: dict[str, float] = {}
    protocol = frozen["protocol"]
    mission, run = identifiers(frozen, lab)
    database = args.out / "copies" / lab / "missions.sqlite"
    journal = output / "review.sqlite"
    reference = frozen["references"][lab]["facts"]
    snapshot = timed(stages, "snapshot", mission_snapshot, database, mission)
    independently_verified = {
        row["receipt"]["id"]: {
            "status": row["receipt"]["response"]["status"],
            "sha256": row["evidence_sha256"],
        }
        for row in snapshot["snapshot"]["http"]
        if row["receipt"]
    } == reference
    verified = timed(
        stages, "w6_export_and_verify", exports, database, run, output, stages
    )
    review = timed(
        stages,
        "deterministic_context",
        review_snapshot,
        snapshot,
        max_context_bytes=8192,
    )
    items = review["context"]["items"]
    critical = sum(item["state"] in ("unknown", "contradiction") for item in items)
    focus = {
        "available": items,
        "selected": items,
        "restituted": items,
        "doc_returned": set(),
        "doc_available": set(),
        "doc_retrieved": set(),
        "critical_shown": critical,
    }
    row = {
        "arm": arm,
        "lab": lab,
        "regime": regime,
        "snapshot_sha256": snapshot["sha256"],
        "w6_verified": verified,
        "snapshot_receipts_match": independently_verified,
        "state": "ready",
        "critical_journal": critical,
        "product_can_recover_full_output": None,
    }
    if arm != "A":
        created = timed(
            stages, "journal_create", create_workflow, database, journal, mission
        )
        rid = UUID(created["review_id"])
        provider = OllamaProvider(
            protocol["generator"], args.generator, protocol["provider_timeout_seconds"]
        )
        if arm == "B":
            result = timed(
                stages,
                "analysis_total",
                lambda: asyncio.run(analyze_workflow(database, journal, rid, provider)),
            )
        else:
            context, router = session(
                database, mission, arm, args, collection, embedding, dense
            )
            selector = RecordedSelector(OllamaSelector(provider, DIGEST, keep_alive=60))
            result = timed(
                stages,
                "analysis_total",
                lambda: asyncio.run(
                    analyze_workflow_v2(
                        journal,
                        rid,
                        context,
                        protocol["objective"],
                        RetrievalMode.AUTO if arm in "EF" else RetrievalMode.LEXICAL,
                        Budget(**protocol["context"]),
                        selector,
                    )
                ),
            )
        row["state"] = result["state"]
        reloaded = timed(
            stages,
            "journal_verify",
            read_workflow,
            journal,
            rid,
            expected_head=result["head_sha256"],
        )
        row["journal_matches_snapshot"] = (
            reloaded["snapshot_sha256"] == snapshot["sha256"]
        )
        row["execution_authorized"] = reloaded["execution_authorized"]
        row["critical_journal"] = len(reloaded["critical_items"])
        if row["state"] == "ready" and arm == "B":
            assert reloaded["latest_analysis"] == result["latest_analysis"]
            analysis = reloaded["latest_analysis"]["analysis"]
            returned = [
                item for group in analysis["analysis"].values() for item in group
            ]
            _, candidates = _request(review["context"])
            focus.update(
                available=candidates,
                selected=[
                    item for item in returned if item["origin"] == "model_selection"
                ],
                restituted=returned,
                critical_shown=row["critical_journal"],
                usage=analysis["metrics"],
            )
            row["product_can_recover_full_output"] = True
        elif row["state"] == "ready":
            focus = scoring_v2(result, selector, router)
            assert reloaded["latest_analysis"]["response_sha256"] == fingerprint(
                result["consultation"]
            )
            row["product_can_recover_full_output"] = "consultation" in reloaded
            row["retrieval"] = result["consultation"]["coverage"].get("retrieval", [])
        elif reloaded["latest_analysis"]:
            row["error"] = reloaded["latest_analysis"].get("error") or (
                reloaded["latest_analysis"].get("analysis") or {}
            ).get("error")
        timed(
            stages,
            "private_output_write",
            save,
            output / "review.json",
            {
                "result": {
                    key: value for key, value in result.items() if key != "events"
                },
            },
        )
    else:
        timed(stages, "private_output_write", save, output / "review.json", review)
    row.update(score_trial(lab, focus, reference))
    row.update(
        critical_shown=focus["critical_shown"],
        abstention=focus.get("abstention"),
        usage=focus.get("usage", {}),
        journal_bytes=journal.stat().st_size if journal.exists() else 0,
        output_bytes=sum(path.stat().st_size for path in output.iterdir()),
    )
    stages.update(focus.get("timings", {}))
    after_cpu = resource.getrusage(resource.RUSAGE_SELF)
    row["bench_cpu_ms"] = (
        after_cpu.ru_utime
        + after_cpu.ru_stime
        - before_cpu.ru_utime
        - before_cpu.ru_stime
    ) * 1000
    row["window"] = [started, perf_counter()]
    stages["total"] = (row["window"][1] - started) * 1000
    row["timings_ms"] = stages
    return row


def unload(port: int, model: str) -> None:
    with httpx.Client(
        base_url=f"http://127.0.0.1:{port}",
        trust_env=False,
        timeout=20,
    ) as client:
        client.post(
            "/api/generate", json={"model": model, "keep_alive": 0}
        ).raise_for_status()
    wait_empty(port)


def source_inventory(args) -> dict:
    files = {}
    protocol = json.loads(PROTOCOL.read_text())
    for lab in protocol["archives"]:
        archive = args.archives / f"{lab}-contextual-r1" / "missions.sqlite"
        memory = MemoryEngine(args.memory, mission_id(archive, args.memory))
        files.update(inventory(archive, memory))
        score = archive.with_name("score.json")
        files[str(score)] = digest(score)
    paths = (
        args.ollama / "runtime" / "bin" / "ollama",
        args.ollama / "m35-retrieval" / "runtime-0.40.18" / "bin" / "ollama",
        args.ollama / "models" / "manifests",
        args.ollama / "m35-retrieval" / "models" / "manifests",
        args.archives / "manifest.json",
    )
    for path in paths:
        for file in [path] if path.is_file() else sorted(path.rglob("*")):
            if file.is_file():
                files[str(file)] = digest(file)
    for root, name, tag in (
        (args.ollama / "models", "qwen3", "4b"),
        (args.ollama / "m35-retrieval" / "models", "qwen3-embedding", "0.6b"),
    ):
        manifest = root / "manifests" / "registry.ollama.ai" / "library" / name / tag
        model = json.loads(manifest.read_text())
        for layer in (model["config"], *model["layers"]):
            algorithm, expected = layer["digest"].split(":", 1)
            blob = root / "blobs" / f"{algorithm}-{expected}"
            actual = digest(blob)
            if algorithm != "sha256" or actual != expected:
                raise ValueError(f"Installed model blob differs: {name}/{tag}")
            files[str(blob)] = actual
    return files


def schedule(protocol: dict, extra_rounds: int):
    labs = tuple(protocol["archives"])
    arms = tuple(protocol["arms"])
    for round_index in range(protocol["repetitions"] + extra_rounds):
        ordered_labs = labs[round_index % len(labs) :] + labs[: round_index % len(labs)]
        for index, lab in enumerate(ordered_labs):
            offset = (round_index + index) % len(arms)
            for arm in arms[offset:] + arms[:offset]:
                if round_index < protocol["repetitions"] or arm == "A":
                    yield round_index, lab, arm


def campaign(args) -> None:
    args.out.mkdir(mode=0o700)
    os.umask(0o077)
    os.environ["ARGOS_DATA_HOME"] = str(args.out / "fixture-data")
    protocol = json.loads(PROTOCOL.read_text())
    before = source_inventory(args)
    freeze(args.out, args, protocol, before)
    frozen = json.loads((args.out / "frozen.json").read_text())
    frozen_hash = digest(args.out / "frozen.json")
    for lab in protocol["archives"]:
        dest = args.out / "copies" / lab
        dest.mkdir(parents=True, mode=0o700)
        source = args.archives / f"{lab}-contextual-r1" / "missions.sqlite"
        shutil.copy2(source, dest / source.name)
    save(
        args.out / "environment.json",
        {
            "python": sys.version,
            "platform": platform.platform(),
            "sqlite": sqlite3.sqlite_version,
            "cores_available": len(os.sched_getaffinity(0)),
            "git": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "frozen_sha256": frozen_hash,
            "development": args.development,
        },
    )
    if args.development:
        protocol = {
            **protocol,
            "repetitions": 1,
            "archives": {"crapi": protocol["archives"]["crapi"]},
        }
    rows: list[dict] = []
    samples: list[dict] = []
    halted = Event()
    ready = False
    try:
        with ExitStack() as stack:
            processes = []
            stack.callback(stop_processes, processes)
            processes.append(
                launch(args.out, args.ollama, args.generator, "campaign", "generator")
            )
            processes.append(
                launch(
                    args.out,
                    args.ollama,
                    args.embedding,
                    "campaign",
                    "embedding",
                    cpu=True,
                )
            )
            wait(args.generator)
            wait(args.embedding)
            save(
                args.out / "providers.json",
                {
                    "generator": api(args.generator, "version"),
                    "embedding": api(args.embedding, "version"),
                },
            )
            model = next(
                item
                for item in api(args.generator, "tags")["models"]
                if item["name"] == protocol["generator"]
            )
            if model["digest"].removeprefix("sha256:") != DIGEST:
                raise ValueError("Generator digest differs")
            embed = stack.enter_context(
                OllamaEmbeddingProvider(
                    QWEN.model,
                    port=args.embedding,
                    keep_alive=300,
                )
            )
            collection = Collection(CollectionKind.USER)
            setup_started = perf_counter()
            store_notes(NOTES, collection)
            index = build(CollectionDatabase(collection), embed, authorize=lambda: None)
            save(
                args.out / "setup.json",
                {
                    "duration_ms": (perf_counter() - setup_started) * 1000,
                    "index": repr(index),
                },
            )
            groups = dict(
                zip((p.pid for p in processes), ("generator", "embedding"), strict=True)
            )
            observer = Thread(target=observe, args=(halted, samples, groups))
            observer.start()
            stack.callback(observer.join)
            stack.callback(halted.set)
            extra = 0 if args.development else protocol["additional_a_rounds"]
            for round_index, lab, arm in schedule(protocol, extra):
                if arm != "A":
                    unload(args.generator, protocol["generator"])
                if arm in "EF":
                    embed.unload()
                    wait_empty(args.embedding)
                dense = None
                if arm in "EF":
                    dense = NumPyKnowledgeRetriever(
                        collection,
                        allowed_collections={collection},
                        provider=embed,
                    )
                for regime in ("cold", "warm"):
                    label = f"{round_index:02d}-{lab}-{arm}-{regime}"
                    resident_before = {
                        name: bool(api(port, "ps").get("models"))
                        for name, port in (
                            ("generator", args.generator),
                            ("embedding", args.embedding),
                        )
                        if arm != "A" and (name == "generator" or arm in "EF")
                    }
                    row = trial(
                        args,
                        frozen,
                        lab,
                        arm,
                        regime,
                        args.out / label,
                        collection,
                        embed,
                        dense,
                    )
                    row["resident_before"] = resident_before
                    rows.append(row)
                    with (args.out / "trials.jsonl").open("a") as stream:
                        stream.write(json.dumps(row) + "\n")
                    print(
                        label,
                        row["state"],
                        round(row["timings_ms"]["total"]),
                        flush=True,
                    )
            ready = True
    finally:
        unchanged = before == source_inventory(args)
        save(args.out / "resources.json", samples)
        save(
            args.out / "summary.json",
            {
                "complete": ready,
                "sources_unchanged": unchanged,
                "frozen_unchanged": digest(args.out / "frozen.json") == frozen_hash,
                "cells": summarize(rows, protocol["gates"]["p95_minimum_samples"]),
            },
        )
        if not unchanged:
            raise ValueError("Source inventory changed during campaign")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archives", "memory", "ollama", "out"):
        parser.add_argument(
            "--" + name, type=lambda value: Path(value).resolve(), required=True
        )
    parser.add_argument("--generator", type=int, default=11565)
    parser.add_argument("--embedding", type=int, default=11566)
    parser.add_argument("--development", action="store_true")
    campaign(parser.parse_args())


if __name__ == "__main__":
    main()
