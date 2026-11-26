"""Small, Linux-only Ollama residency probe. Uses only preinstalled local data."""

import argparse
import asyncio
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from threading import Event, Thread

import httpx
from argos.backend.attack.review.context_v2 import (
    CollectionReader,
    Purpose,
    ReviewContextV2,
)
from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.attack.review.workflow_v2 import analyze_documentary
from argos.backend.consultation.context import Budget
from argos.backend.knowledge import (
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeStore,
    Source,
)
from argos.backend.knowledge.embeddings import QWEN, OllamaEmbeddingProvider
from argos.backend.knowledge.retrieval import SQLiteKnowledgeRetriever
from argos.backend.knowledge.router import RetrievalMode, RetrievalRouter
from argos.backend.knowledge.storage import CollectionDatabase
from argos.backend.knowledge.vector_index import build
from argos.backend.knowledge.vector_retrieval import NumPyKnowledgeRetriever


def api(port, route):
    return httpx.get(
        f"http://127.0.0.1:{port}/api/{route}", timeout=4, trust_env=False
    ).json()


def gpu_memory(field="memory.used"):
    return int(
        subprocess.check_output(
            ["nvidia-smi", f"--query-gpu={field}", "--format=csv,noheader,nounits"],
            text=True,
        ).strip()
    )


def wait(port):
    for _ in range(80):
        try:
            api(port, "version")
            return
        except (httpx.RequestError, ValueError):
            time.sleep(0.25)
    raise RuntimeError("Ollama did not start")


def launch(base, repo, port, run, name, cpu=False):
    alt = repo / "m35-retrieval"
    if name == "generator":
        runtime = repo / "runtime"
        models = repo / "models"
    else:
        runtime = alt / "runtime-0.40.18"
        models = alt / "models"
    env = dict(
        os.environ,
        OLLAMA_MODELS=str(models),
        OLLAMA_HOST=f"127.0.0.1:{port}",
        OLLAMA_NO_CLOUD="1",
        OLLAMA_NOPRUNE="1",
        OLLAMA_MAX_LOADED_MODELS="1",
        OLLAMA_NUM_PARALLEL="1",
    )
    if cpu:
        env.update(CUDA_VISIBLE_DEVICES="-1", ROCR_VISIBLE_DEVICES="-1")
    with socket.socket() as check:
        check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        check.bind(("127.0.0.1", port))
    with (base / f"{run}-{name}.log").open("x") as log:
        return subprocess.Popen(
            [str(runtime / "bin/ollama"), "serve"],
            env=env,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )


def pss(processes):
    result = {"generator": 0, "embedding": 0}
    rows = subprocess.check_output(["ps", "-eo", "pid=,pgid="], text=True)
    names = dict(zip((p.pid for p in processes), result, strict=True))
    for row in rows.splitlines():
        pid, group = map(int, row.split())
        if group in names:
            try:
                for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
                    if line.startswith("Pss:"):
                        result[names[group]] += int(line.split()[1])
                        break
            except OSError:
                pass
    return result


def wait_empty(port):
    started = time.perf_counter()
    while api(port, "ps").get("models"):
        if time.perf_counter() - started > 10:
            raise RuntimeError("Model still resident")
        time.sleep(0.03)
    return (time.perf_counter() - started) * 1000


def sample(processes, stop, samples, first):
    while not stop.is_set():
        samples.append(
            {
                "at_s": time.perf_counter() - first,
                "vram_mib": gpu_memory(),
                "pss_kib": pss(processes),
            }
        )
        stop.wait(0.1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--corpus", type=Path, default=Path("data/knowledge/m35-retrieval/corpus")
    )
    parser.add_argument("--ollama-home", type=Path, default=Path("data/ollama"))
    parser.add_argument("--generator-port", type=int, default=11545)
    parser.add_argument("--embedding-port", type=int, default=11546)
    args = parser.parse_args()
    base, repo, corpus = (
        args.out.resolve(),
        args.ollama_home.resolve(),
        args.corpus.resolve(),
    )
    generation_port, embedding_port = args.generator_port, args.embedding_port
    if generation_port == embedding_port:
        raise ValueError("The two Ollama daemons require different ports")
    base.mkdir(mode=0o700)
    os.environ["ARGOS_DATA_HOME"] = str(base / "fixture-data")
    digest = "359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7"
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    store.sources.register(
        Source(
            "mdn",
            "MDN Web Docs",
            "https://developer.mozilla.org/",
            "CC-BY-SA-2.5",
            True,
        )
    )
    store.sources.approve("mdn")
    for slug in ("etag", "if-none-match", "vary"):
        document = DocumentRef("mdn", slug)
        meta = DocumentMetadata(slug, "text/markdown", f"mdn:{slug}")
        staged = store.ingest_bytes(
            document, meta, (corpus / f"{slug}.md").read_bytes()
        )
        store.approve_version(document, staged.version.id)

    for run in ("sequential", "cpu-gpu", "simultaneous"):
        if run == "simultaneous" and gpu_memory("memory.total") - gpu_memory() < 6700:
            (base / f"{run}.json").write_text(
                json.dumps({"skipped": "insufficient free VRAM"})
            )
            continue
        processes = []
        try:
            processes.append(launch(base, repo, generation_port, run, "generator"))
            processes.append(
                launch(
                    base, repo, embedding_port, run, "embedding", cpu=run == "cpu-gpu"
                )
            )
            wait(generation_port)
            wait(embedding_port)
            print(
                run,
                api(generation_port, "version"),
                api(embedding_port, "version"),
                flush=True,
            )
            selector = OllamaSelector(
                OllamaProvider("qwen3:4b", port=generation_port),
                digest,
                keep_alive=60 if run != "sequential" else 0,
            )
            with OllamaEmbeddingProvider(
                QWEN.model,
                port=embedding_port,
                keep_alive=0 if run == "sequential" else 60,
            ) as provider:
                if run == "sequential":
                    initial = build(
                        CollectionDatabase(collection), provider, authorize=lambda: None
                    )
                    print("built", initial.attached, flush=True)
                    wait_empty(embedding_port)
                samples, records = [], []
                state = Event()
                first = time.perf_counter()
                observer = Thread(
                    target=sample, args=(processes, state, samples, first)
                )
                observer.start()
                try:
                    allowed = {collection}
                    sql = SQLiteKnowledgeRetriever(
                        collection, allowed_collections=allowed
                    )
                    dense = NumPyKnowledgeRetriever(
                        collection, allowed_collections=allowed, provider=provider
                    )
                    view = ReviewContextV2(
                        readers=(
                            CollectionReader(
                                collection,
                                sql,
                                RetrievalRouter(sql, dense),
                                provider.space,
                            ),
                        )
                    )
                    for _ in range(3):
                        start = time.perf_counter()
                        prepared = view.prepare(
                            "What does the ETag response header identify?",
                            Purpose.DOCUMENTARY,
                            RetrievalMode.AUTO,
                            Budget(),
                            selector.size,
                        )
                        idle = (
                            wait_empty(embedding_port) if run == "sequential" else None
                        )
                        before = api(embedding_port, "ps")
                        start_gen = time.perf_counter() - first
                        reply = asyncio.run(
                            analyze_documentary(prepared, view, selector)
                        )
                        elapsed = (time.perf_counter() - start) * 1000
                        end_gen = time.perf_counter() - first
                        records.append(
                            {
                                "response": reply,
                                "elapsed_ms": elapsed,
                                "t_before_generate": start_gen,
                                "t_after_generate": end_gen,
                                "embedding_disappearance_ms": idle,
                                "embedding_before_generate": before,
                                "embedding_after_generate": api(embedding_port, "ps"),
                                "generator_after_generate": api(generation_port, "ps"),
                            }
                        )
                        print(
                            run,
                            elapsed,
                            reply["usage"],
                            reply["abstention"],
                            flush=True,
                        )
                finally:
                    state.set()
                    observer.join()
                    (base / f"{run}.json").write_text(
                        json.dumps({"records": records, "samples": samples}, indent=2)
                    )
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
            for process in reversed(processes):
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


if __name__ == "__main__":
    main()
