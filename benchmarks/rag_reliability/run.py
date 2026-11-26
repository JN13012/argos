"""Local, paired M3.5.6.1 stress run with already installed Ollama models."""

import argparse
import asyncio
import json
import os
import re
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from statistics import mean
from threading import Event, Thread
from time import perf_counter

import httpx
from argos.backend.attack.review.context_v2 import _citation, _restore
from argos.backend.attack.review.llm import LLMError
from argos.backend.attack.review.ollama import MAX_RESPONSE_BYTES, OllamaProvider, _post
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.consultation.analyst import (
    ClaimStatus,
    InvalidSelection,
    analyze,
    literal_request,
)
from argos.backend.consultation.context import Budget, assemble, encode
from argos.backend.knowledge import Collection, CollectionKind, SQLiteKnowledgeRetriever
from argos.backend.knowledge.embeddings import GEMMA, QWEN, OllamaEmbeddingProvider
from argos.backend.knowledge.storage import CollectionDatabase
from argos.backend.knowledge.vector_index import build
from argos.backend.knowledge.vector_retrieval import NumPyKnowledgeRetriever
from benchmarks.rag_eval.dataset import ROOT as HISTORICAL_ROOT
from benchmarks.rag_eval.dataset import load
from benchmarks.rag_eval.metrics import judge, rank_scores, rollup
from benchmarks.rag_eval.resources import stop_processes
from benchmarks.rag_eval.run import (
    DIGEST,
    INSTRUCTION,
    SCHEMA,
    cited_id,
    context_units,
    doc_units,
    generate,
    parse_reply,
    save,
    size,
    store_notes,
)
from benchmarks.retrieval.consultation_probe import (
    api,
    gpu_memory,
    launch,
    sample,
    wait,
    wait_empty,
)

from .dataset import ROOT, fingerprints, read

CANARY = re.compile(r"M3561?_\w*CANARY")


@contextmanager
def observe(processes, output: Path):
    samples: list[dict] = []
    stop = Event()
    observer = Thread(target=sample, args=(processes, stop, samples, perf_counter()))
    observer.start()
    try:
        yield
    finally:
        stop.set()
        observer.join()
        save(output, samples)


def usage(value, budget, bound):
    counts = value.get("prompt_eval_count", 0), value.get("eval_count", 0)
    if (
        value.get("done_reason") != "stop"
        or any(type(count) is not int for count in counts)
        or not 0 < counts[0] <= bound
        or not 0 < counts[1] <= budget.reserve
    ):
        return "invalid", [], counts
    verdict, refs = parse_reply(value.get("response", ""))
    return verdict, refs, counts


async def native_chat(client, model, budget, data):
    reply = await _post(
        client,
        "/api/chat",
        {
            "model": model,
            "messages": [
                {"role": "system", "content": INSTRUCTION},
                {"role": "user", "content": data},
            ],
            "think": False,
            "stream": False,
            "format": SCHEMA,
            "keep_alive": 120,
            "options": {
                "temperature": 0,
                "num_ctx": budget.window,
                "num_predict": budget.reserve,
            },
        },
        MAX_RESPONSE_BYTES,
    )
    reply["response"] = reply.get("message", {}).get("content", "")
    return reply


async def unload_generator(selector: OllamaSelector, model: str) -> None:
    async with selector._client() as client:
        await _post(
            client,
            "/api/generate",
            {"model": model, "keep_alive": 0},
            MAX_RESPONSE_BYTES,
        )
    wait_empty(selector.endpoint.port)


def pin_generators(repo: Path, port: int, names: list[str]) -> dict:
    tags = {item["name"]: item for item in api(port, "tags")["models"]}
    result = {}
    for name in names:
        model, tag = name.split(":")
        manifest = repo / "models/manifests/registry.ollama.ai/library" / model / tag
        if sha256(manifest.read_bytes()).hexdigest() != tags[name]["digest"]:
            raise ValueError(f"Unexpected manifest digest for {name}")
        result[name] = tags[name]
    if result["qwen3:4b"]["digest"] != DIGEST:
        raise ValueError("Historical baseline pin changed")
    return result


def corpus(split, collection, provider, notes, cases, out, limit):
    with provider:
        ranking = {}
        retriever = NumPyKnowledgeRetriever(
            collection, allowed_collections={collection}, provider=provider
        )
        started = perf_counter()
        build(CollectionDatabase(collection), provider, authorize=lambda: None)
        index_ms = (perf_counter() - started) * 1000
        by_id = {note.id: note for note in notes}
        for case in cases:
            query = literal_request(case.question) or case.question
            started = perf_counter()
            hits = retriever.retrieve(query, limit=10)
            elapsed = (perf_counter() - started) * 1000
            ids = [hit.document.document_id for hit in hits]
            ranking[case.id] = (
                doc_units(hits, by_id, limit),
                elapsed,
                rank_scores(ids, set(case.relevant)),
                ids,
            )
        save(
            out,
            {
                "space": asdict(provider.space),
                "index_ms": index_ms,
                "split": split,
                "rows": {
                    key: {"ids": row[3], "metrics": row[2], "ms": row[1]}
                    for key, row in ranking.items()
                },
            },
        )
    return ranking


async def compare(args, budget, model, label, cases, ranking, sql, selector):
    baseline_pin = await selector.identify()
    checkpoint = sql.checkpoint()

    def validate(units) -> None:
        if sql.checkpoint() != checkpoint:
            raise ValueError("Qualification collection changed")
        for unit in units:
            pin = json.loads(unit.pin)
            original = sql.resolve(_restore(pin["reference"]))
            if encode(_citation(original)) != unit.pin or original.text != unit.text:
                raise ValueError("Invalid qualification passage")

    rows = []
    path = args.out / f"{label}.jsonl"
    async with selector._client() as client:
        with path.open("x") as stream:
            for case in cases:
                passages, retrieval_ms, _, _ = ranking[case.id]
                archived = case.group == "archive" and bool(case.evidence)
                purpose = (
                    "archived_observations" if archived else "documentary_question"
                )
                units = context_units(
                    case, "A0" if label == "before-a0" else "A4", passages
                )
                validate_passages = [] if label == "before-a0" else passages
                after = label.startswith("after")
                env = assemble(
                    purpose,
                    case.question,
                    units,
                    budget,
                    selector.size if after else size,
                    coverage={},
                )
                available = {i: cited_id(unit) for i, unit in enumerate(env.units, 1)}
                started = perf_counter()
                error_code = None
                try:
                    if after:
                        raw = await analyze(
                            env,
                            selector,
                            baseline_pin,
                            lambda passages=validate_passages: validate(passages),
                        )
                        verdict = (
                            "y"
                            if raw["grounding"]["objective_status"]
                            == ClaimStatus.SUPPORTED_DOCUMENTARY_STATEMENT
                            else "u"
                        )
                        refs = [
                            row["id"]
                            for row in raw["claims"] + raw["contradictions"]
                            if row["status"]
                            in {
                                ClaimStatus.VERIFIED_FACT,
                                ClaimStatus.SUPPORTED_DOCUMENTARY_STATEMENT,
                                ClaimStatus.CONTRADICTION,
                            }
                        ]
                        counts = (
                            raw["usage"]["input_tokens"],
                            raw["usage"]["output_tokens"],
                        )
                        generation_ms = raw["timings_ms"]["generation"]
                        validation_ms = raw["timings_ms"]["validation"]
                        canary = bool(CANARY.search(raw["summary"]))
                    else:
                        if label.startswith("dev"):
                            raw = await native_chat(
                                client, model, budget, env.data_json
                            )
                        else:
                            raw = await generate(
                                client,
                                baseline_pin,
                                budget,
                                env.data_json,
                                keep_alive=120,
                            )
                        generation_ms = (perf_counter() - started) * 1000
                        start_validate = perf_counter()
                        verdict, refs, counts = usage(raw, budget, env.input_bound)
                        validate(validate_passages)
                        validation_ms = (perf_counter() - start_validate) * 1000
                        canary = bool(CANARY.search(raw.get("response", "")))
                except (LLMError, InvalidSelection, httpx.RequestError) as error:
                    verdict, refs, counts = "invalid", [], (0, 0)
                    generation_ms, validation_ms = (perf_counter() - started) * 1000, 0
                    raw = {}
                    canary = False
                    error_code = (
                        error.code.value
                        if isinstance(error, LLMError)
                        else type(error).__name__
                    )
                score = judge(case, verdict, refs, available)
                row = {
                    "case": case.id,
                    "expected": case.expected,
                    "group": case.group,
                    "model": model,
                    "verdict": verdict,
                    "references": refs,
                    "available": available,
                    "score": score,
                    "canary": canary,
                    "attributed_canary": after
                    and bool(CANARY.search(encode(raw.get("claims", [])))),
                    "selected_critical_archive": archived
                    and case.expected != "u"
                    and "archive" in {available.get(i) for i in refs},
                    "input_tokens": counts[0],
                    "output_tokens": counts[1],
                    "phase_ms": {
                        "retrieval": 0 if label == "before-a0" else retrieval_ms,
                        "assembly": env.assembly_ms,
                        "generation": generation_ms,
                        "validation": validation_ms,
                    },
                    "raw": raw,
                    "error": error_code,
                    "payload": env.data_json,
                }
                print(json.dumps(row, ensure_ascii=False), file=stream, flush=True)
                rows.append(row)
    if await selector.identify() != baseline_pin:
        raise ValueError("Qwen baseline pin changed")
    return rows


def summary(rows):
    return {
        **rollup(rows),
        "invalid_replies": sum(row["verdict"] == "invalid" for row in rows),
        "critical_archive_selected": sum(
            row["selected_critical_archive"] for row in rows
        ),
        "attributed_canaries": sum(row["attributed_canary"] for row in rows),
        "assertions": sum(row["score"]["asserted"] for row in rows),
        "unsupported_assertions": sum(row["score"]["unsupported"] for row in rows),
        "injection_case_correct": [
            row["score"]["correct"] for row in rows if row["group"] == "injection"
        ],
        "full_contradiction": [
            row["score"]["covered_critical"]
            for row in rows
            if row["group"] == "contradiction"
        ],
    }


def run(args) -> None:
    args.out.mkdir(mode=0o700, parents=True)
    os.environ["ARGOS_DATA_HOME"] = str(args.out.resolve() / "fixture-data")
    protocol = json.loads((ROOT / "protocol.json").read_text())
    settings = protocol["fixed"]
    budget = Budget(
        settings["context_window"],
        settings["answer_reserve"],
        settings["max_bytes"],
        settings["max_items"],
    )
    notes, cases = read(args.split)
    if args.split == "development":
        old_notes, old_cases = load("development")
        notes, cases = notes + old_notes, cases + old_cases
    collection = Collection(CollectionKind.USER)
    store_notes(notes, collection)
    sql = SQLiteKnowledgeRetriever(collection, allowed_collections={collection})
    selector = OllamaSelector(
        OllamaProvider("qwen3:4b", args.generator), DIGEST, keep_alive=120
    )
    processes = []
    results = {
        "split": args.split,
        "frozen": fingerprints(),
        "vram_before_mib": gpu_memory(),
        "vram_total_mib": gpu_memory("memory.total"),
        "arms": {},
        "embeddings": {},
    }
    try:
        processes.append(
            launch(args.out, args.ollama, args.generator, "run", "generator")
        )
        processes.append(
            launch(args.out, args.ollama, args.embedding, "run", "embedding", cpu=True)
        )
        wait(args.generator)
        wait(args.embedding)
        results["pins"] = pin_generators(
            args.ollama, args.generator, protocol["models"]
        )
        results["runtime"] = {
            name: api(port, "version")
            for name, port in (
                ("generator", args.generator),
                ("embedding", args.embedding),
            )
        }
        profiles = (QWEN,) if args.split == "development" else (QWEN, GEMMA)
        for profile in profiles:
            name = profile.model.split(":")[0]
            with observe(processes, args.out / f"{name}-retrieval-resources.json"):
                ranking = corpus(
                    args.split,
                    collection,
                    OllamaEmbeddingProvider(
                        profile.model, port=args.embedding, keep_alive=120
                    ),
                    notes,
                    cases,
                    args.out / f"{name}-retrieval.json",
                    settings["rag_results"],
                )
            measured = [row[2] for row in ranking.values() if row[2]]
            results["embeddings"][name] = {
                key: mean(row[key] for row in measured) for key in measured[0]
            }
            if args.split == "development":
                arms = [
                    (f"dev-{model.replace(':', '-')}", model)
                    for model in protocol["models"]
                ]
            else:
                arms = [(f"before-{name}", "qwen3:4b"), (f"after-{name}", "qwen3:4b")]
                if profile is QWEN:
                    arms.insert(0, ("before-a0", "qwen3:4b"))
            for label, model in arms:
                with observe(processes, args.out / f"{label}-resources.json"):
                    rows = asyncio.run(
                        compare(
                            args, budget, model, label, cases, ranking, sql, selector
                        )
                    )
                    resident = api(args.generator, "ps")
                results["arms"][label] = {**summary(rows), "resident": resident}
                save(args.out / "summary.json", results)
                print(label, results["arms"][label]["accuracy"], flush=True)
                if args.split == "development":
                    asyncio.run(unload_generator(selector, model))
        results["acceptance_reference"] = json.loads(
            (HISTORICAL_ROOT / "protocol.json").read_text()
        )["accept"]
        if (
            pin_generators(args.ollama, args.generator, protocol["models"])
            != results["pins"]
        ):
            raise ValueError("Generator manifests changed during qualification")
        save(args.out / "summary.json", results)
    finally:
        stop_processes(processes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("development", "final"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ollama", type=Path, default=Path("data/ollama").resolve())
    parser.add_argument("--generator", type=int, default=11545)
    parser.add_argument("--embedding", type=int, default=11546)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
