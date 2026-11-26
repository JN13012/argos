"""Explicit local CLI entry points for consultative V2."""

import argparse
import asyncio
import json
import os
from contextlib import ExitStack
from dataclasses import asdict
from time import perf_counter
from uuid import UUID

from argos.backend.attack.web.cli import private_path
from argos.backend.consultation.context import Budget
from argos.backend.knowledge.contracts import Collection, CollectionKind
from argos.backend.knowledge.embeddings import (
    OLLAMA_PROFILES,
    QWEN,
    OllamaEmbeddingProvider,
)
from argos.backend.knowledge.retrieval import SQLiteKnowledgeRetriever
from argos.backend.knowledge.router import RetrievalMode, RetrievalRouter
from argos.backend.knowledge.vector_retrieval import (
    CosineCalibration,
    NumPyKnowledgeRetriever,
)
from argos.data_paths import prepare_area

from .context_v2 import CollectionReader, Purpose, ReviewContextV2
from .memory import MemoryEngine
from .ollama import OllamaProvider
from .ollama_v2 import QWEN3_4B, OllamaSelector
from .workflow import read_workflow
from .workflow_v2 import analyze_documentary, analyze_workflow_v2

_DEFAULT_GENERATOR_DIGEST = (
    "359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7"
)


def scope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--collection",
        action="append",
        type=CollectionKind,
        choices=[
            CollectionKind.USER,
            CollectionKind.GLOBAL,
            CollectionKind.MISSION,
            CollectionKind.ACQUIRED,
        ],
        default=[],
    )
    parser.add_argument("--memory", action="store_true")
    parser.add_argument("--memory-root")


def add_v2_parsers(actions: argparse._SubParsersAction) -> None:
    for command in ("context-v2", "documentary-v2", "workflow-analyze-v2"):
        parser = actions.add_parser(command, help=f"Consultative V2: {command}")
        parser.set_defaults(action="review_v2_" + command)
        parser.add_argument("--objective", required=True)
        parser.add_argument("--window", type=int, default=8192)
        parser.add_argument("--reserve", type=int, default=384)
        parser.add_argument("--max-context-bytes", type=int, default=32768)
        parser.add_argument("--max-items", type=int, default=48)
        parser.add_argument(
            "--mode",
            type=RetrievalMode,
            choices=tuple(RetrievalMode),
            default=RetrievalMode.AUTO,
        )
        parser.add_argument(
            "--embedding", choices=tuple(OLLAMA_PROFILES), default=QWEN.model
        )
        parser.add_argument("--embedding-port", type=int, default=11536)
        parser.add_argument("--embedding-timeout", type=float, default=15)
        parser.add_argument("--minimum-cosine", type=float)
        parser.add_argument("--calibration-corpus")
        scope_arguments(parser)
        if command == "context-v2":
            parser.add_argument("--db")
            parser.add_argument("--mission-id", type=UUID)
        if command == "workflow-analyze-v2":
            parser.add_argument("--db", required=True)
            parser.add_argument("--journal", required=True)
            parser.add_argument("--review-id", type=UUID, required=True)
        if command != "context-v2":
            parser.add_argument("--model", default=QWEN3_4B)
            parser.add_argument("--model-digest")
            parser.add_argument("--ollama-port", type=int, default=11434)
            parser.add_argument("--timeout-seconds", type=int, default=90)


def context_for(
    args: argparse.Namespace,
    mission_id: UUID | None,
    stack: ExitStack,
    *,
    retrieve: bool,
) -> ReviewContextV2:
    database = private_path(args.db) if getattr(args, "db", None) else None
    memory = None
    if args.memory or args.memory_root:
        if mission_id is None:
            raise ValueError("Consultative memory requires a mission")
        root = (
            args.memory_root
            or os.environ.get("ARGOS_MEMORY_HOME")
            or prepare_area("memory")
        )
        memory = MemoryEngine(root, mission_id)
    kinds = args.collection or ([CollectionKind.USER] if mission_id is None else [])
    collections = tuple(
        Collection(kind, mission_id if kind is CollectionKind.MISSION else None)
        for kind in kinds
    )
    provider = None
    calibration = None
    if retrieve:
        calibrated = args.minimum_cosine is not None
        if calibrated != bool(args.calibration_corpus):
            raise ValueError("A cosine threshold requires a corpus identity")
        if args.mode in {RetrievalMode.AUTO, RetrievalMode.DENSE} and collections:
            provider = stack.enter_context(
                OllamaEmbeddingProvider(
                    args.embedding,
                    port=args.embedding_port,
                    keep_alive=0,
                    timeout=args.embedding_timeout,
                )
            )
            if calibrated:
                calibration = CosineCalibration(
                    provider.space.identity,
                    args.calibration_corpus,
                    args.minimum_cosine,
                )
    readers = []
    for collection in collections:
        sql = SQLiteKnowledgeRetriever(collection, allowed_collections=collections)
        dense = (
            NumPyKnowledgeRetriever(
                collection,
                allowed_collections=collections,
                provider=provider,
                calibration=calibration,
            )
            if provider is not None
            else None
        )
        readers.append(
            CollectionReader(
                collection,
                sql,
                RetrievalRouter(sql, dense),
                provider.space if provider else None,
            )
        )
    return ReviewContextV2(
        database=database, mission_id=mission_id, memory=memory, readers=tuple(readers)
    )


def execute_v2(args: argparse.Namespace) -> dict:
    action = args.action.removeprefix("review_v2_")
    budget = Budget(args.window, args.reserve, args.max_context_bytes, args.max_items)
    with ExitStack() as stack:
        if action == "workflow-analyze-v2":
            journal = private_path(args.journal)
            saved = read_workflow(journal, args.review_id)
            mission_id = UUID(saved["mission_id"])
        else:
            mission_id = getattr(args, "mission_id", None)
        context = context_for(args, mission_id, stack, retrieve=True)
        if action == "context-v2":
            purpose = Purpose.ARCHIVE if mission_id else Purpose.DOCUMENTARY
            prepared = context.prepare(
                args.objective, purpose, args.mode, budget, OllamaSelector.size
            )
            started = perf_counter()
            context.validate(prepared.pins)
            validation_ms = (perf_counter() - started) * 1000
            return {
                "context": json.loads(prepared.envelope.data_json),
                "pins": prepared.pins,
                "budget": asdict(budget),
                "prompt_bytes": prepared.envelope.prompt_bytes,
                "input_token_bound": prepared.envelope.input_bound,
                "timings_ms": {
                    **prepared.timings_ms,
                    "assembly": prepared.envelope.assembly_ms,
                    "validation": validation_ms,
                },
            }
        if args.model_digest is None and args.model != QWEN3_4B:
            raise ValueError("An alternate generator requires its installed digest")
        selector = OllamaSelector(
            OllamaProvider(args.model, args.ollama_port, args.timeout_seconds),
            args.model_digest or _DEFAULT_GENERATOR_DIGEST,
        )
        if action == "workflow-analyze-v2":
            result = asyncio.run(
                analyze_workflow_v2(
                    journal,
                    args.review_id,
                    context,
                    args.objective,
                    args.mode,
                    budget,
                    selector,
                )
            )
            result.pop("events")
            return result
        prepared = context.prepare(
            args.objective, Purpose.DOCUMENTARY, args.mode, budget, selector.size
        )
        return asyncio.run(analyze_documentary(prepared, context, selector))
