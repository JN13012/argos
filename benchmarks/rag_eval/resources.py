"""Compare residency profiles on one question without contacting any target."""

import argparse
import asyncio
import os
import signal
import subprocess
from pathlib import Path
from threading import Event, Thread
from time import perf_counter

from argos.backend.attack.review.context_v2 import (
    CollectionReader,
    Purpose,
    ReviewContextV2,
)
from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.attack.review.workflow_v2 import analyze_documentary
from argos.backend.consultation.context import Budget
from argos.backend.knowledge import Collection, CollectionKind, SQLiteKnowledgeRetriever
from argos.backend.knowledge.embeddings import QWEN, OllamaEmbeddingProvider
from argos.backend.knowledge.router import RetrievalMode, RetrievalRouter
from argos.backend.knowledge.vector_retrieval import NumPyKnowledgeRetriever
from benchmarks.retrieval.consultation_probe import (
    api,
    gpu_memory,
    launch,
    sample,
    wait,
    wait_empty,
)

from .run import DIGEST, save

QUESTION = "Does TLS 1.3 early data need application replay precautions?"


def stop_processes(processes) -> None:
    for p in reversed(processes):
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
    for p in processes:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=5)


def probe(args) -> None:
    os.environ["ARGOS_DATA_HOME"] = str(args.data_home.resolve())
    args.out.mkdir(parents=True, mode=0o700)
    collection = Collection(CollectionKind.USER)
    sql = SQLiteKnowledgeRetriever(collection, allowed_collections={collection})
    budget = Budget()
    for profile in ("sequential", "cpu-gpu", "simultaneous"):
        total = gpu_memory("memory.total")
        baseline = gpu_memory()
        if profile == "simultaneous" and total - baseline < 6700:
            save(args.out / f"{profile}.json", {"skipped": "insufficient free VRAM"})
            continue
        records, processes, samples = [], [], []
        halted = Event()
        observer = None
        try:
            processes.append(
                launch(args.out, args.ollama, args.generator, profile, "generator")
            )
            processes.append(
                launch(
                    args.out,
                    args.ollama,
                    args.embedding,
                    profile,
                    "embedding",
                    cpu=profile == "cpu-gpu",
                )
            )
            wait(args.generator)
            wait(args.embedding)
            alive = 0 if profile == "sequential" else 60
            selector = OllamaSelector(
                OllamaProvider("qwen3:4b", args.generator), DIGEST, keep_alive=alive
            )
            observer = Thread(
                target=sample, args=(processes, halted, samples, perf_counter())
            )
            observer.start()
            with OllamaEmbeddingProvider(
                QWEN.model, port=args.embedding, keep_alive=alive
            ) as provider:
                dense = NumPyKnowledgeRetriever(
                    collection, allowed_collections={collection}, provider=provider
                )
                view = ReviewContextV2(
                    readers=(
                        CollectionReader(
                            collection, sql, RetrievalRouter(sql, dense), provider.space
                        ),
                    )
                )
                for _ in range(3):
                    if not alive:
                        wait_empty(args.generator)
                    start = perf_counter()
                    prep = view.prepare(
                        QUESTION,
                        Purpose.DOCUMENTARY,
                        RetrievalMode.DENSE,
                        budget,
                        selector.size,
                    )
                    if not alive:
                        wait_empty(args.embedding)
                    pre = api(args.embedding, "ps")
                    result = asyncio.run(analyze_documentary(prep, view, selector))
                    records.append(
                        {
                            "reply": result,
                            "total_ms": (perf_counter() - start) * 1000,
                            "embedding_before_generation": pre,
                            "embedding": api(args.embedding, "ps"),
                            "generator": api(args.generator, "ps"),
                        }
                    )
        finally:
            halted.set()
            if observer:
                observer.join()
            save(
                args.out / f"{profile}.json",
                {
                    "samples": samples,
                    "trials": records,
                    "total_vram_mib": total,
                    "baseline_vram_mib": baseline,
                },
            )
            stop_processes(processes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-home", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ollama", type=Path, default=Path("data/ollama").resolve())
    parser.add_argument("--generator", type=int, default=11547)
    parser.add_argument("--embedding", type=int, default=11548)
    probe(parser.parse_args())


if __name__ == "__main__":
    main()
