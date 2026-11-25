"""CLI for offline review of private mission records."""

import argparse
import asyncio
import os
import sqlite3
from pathlib import Path
from uuid import UUID

from argos.backend.attack.web.cli import emit, private_path
from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.attack.web.report_files import load_report_file
from argos.backend.core.tool_registry import ToolRegistry

from .analysis import DEFAULT_ANALYSIS_CONTEXT_BYTES, analyze_mission
from .capabilities import capability_registry
from .context import DEFAULT_CONTEXT_BYTES, mission_review, review_with_memory
from .journal import (
    MAX_INPUT_BYTES,
    JournalIntegrityError,
    read_journal,
    record_decision,
)
from .memory import MemoryEngine
from .ollama import OllamaProvider
from .snapshot import mission_snapshot
from .workflow import (
    accept_workflow,
    analyze_workflow,
    annotate_workflow,
    create_workflow,
    interrupt_workflow,
    read_workflow,
)


def add_parser(commands: argparse._SubParsersAction) -> None:
    group = commands.add_parser("review", help="Offline mission review")
    actions = group.add_subparsers(required=True)
    snapshot = actions.add_parser("snapshot", help="Read an archived mission snapshot")
    snapshot.set_defaults(action="review_snapshot")
    snapshot.add_argument("--db", required=True)
    snapshot.add_argument("--mission-id", type=UUID, required=True)
    summary = actions.add_parser("summary", help="Summarize verified mission knowledge")
    summary.set_defaults(action="review_summary")
    summary.add_argument("--db", required=True)
    summary.add_argument("--mission-id", type=UUID, required=True)
    summary.add_argument("--max-context-bytes", type=int, default=DEFAULT_CONTEXT_BYTES)
    summary.add_argument(
        "--journal", help="Read decision counts from a private journal"
    )
    summary.add_argument(
        "--expected-head", help="Externally recorded journal head SHA-256"
    )
    summary.add_argument("--memory-root", help="Explicit private memory enrichment")
    summary.add_argument("--max-memory-bytes", type=int, default=2048)
    summary.add_argument("--max-memory-items", type=int, default=8)
    summary.add_argument("--memory-query", default="")
    analyze = actions.add_parser(
        "analyze", help="Analyze archived observations locally"
    )
    analyze.set_defaults(action="review_analyze")
    analyze.add_argument("--db", required=True)
    analyze.add_argument("--mission-id", type=UUID, required=True)
    analyze.add_argument("--model", required=True, help="Installed Ollama name:tag")
    analyze.add_argument("--ollama-port", type=int, default=11434)
    analyze.add_argument("--timeout-seconds", type=int, default=90)
    analyze.add_argument(
        "--max-context-bytes", type=int, default=DEFAULT_ANALYSIS_CONTEXT_BYTES
    )
    capabilities = actions.add_parser(
        "capabilities", help="Describe shipped capabilities"
    )
    capabilities.set_defaults(action="review_capabilities")
    capabilities.add_argument("--registry", help="Check an explicit administrator TOML")
    append = actions.add_parser(
        "journal-append", help="Archive an explicit operator decision"
    )
    append.set_defaults(action="review_journal_append")
    append.add_argument("--db", required=True)
    append.add_argument("--mission-id", type=UUID, required=True)
    append.add_argument("--journal", required=True)
    append.add_argument(
        "--input", required=True, help="Private operator decision JSON file"
    )
    show = actions.add_parser(
        "journal-show", help="Verify and read the operator journal"
    )
    show.set_defaults(action="review_journal_show")
    show.add_argument("--journal", required=True)
    show.add_argument("--mission-id", type=UUID)
    show.add_argument(
        "--expected-head", help="Externally recorded journal head SHA-256"
    )

    for command in ("start", "show", "analyze", "annotate", "interrupt", "accept"):
        parser = actions.add_parser(
            "workflow-" + command, help="Persistent supervised review: " + command
        )
        parser.set_defaults(action="review_workflow_" + command)
        parser.add_argument("--journal", required=True)
        if command in {"start", "analyze", "accept"}:
            parser.add_argument("--db", required=True)
        if command == "start":
            parser.add_argument("--mission-id", type=UUID, required=True)
        else:
            parser.add_argument("--review-id", type=UUID, required=True)
        if command in {"annotate", "interrupt", "accept"}:
            parser.add_argument(
                "--input", required=True, help="Private operator JSON file"
            )
        if command == "show":
            parser.add_argument("--expected-head")
            parser.add_argument(
                "--history",
                action="store_true",
                help="Include sensitive frozen snapshot and history",
            )
        if command == "analyze":
            parser.add_argument("--model", required=True)
            parser.add_argument("--ollama-port", type=int, default=11434)
            parser.add_argument("--timeout-seconds", type=int, default=90)

    for command in ("capture", "info", "search", "get", "focus", "delete"):
        parser = actions.add_parser(
            "memory-" + command, help="Consultative mission memory: " + command
        )
        parser.set_defaults(action="review_memory_" + command)
        parser.add_argument(
            "--memory-root",
            default=os.environ.get(
                "ARGOS_MEMORY_HOME", str(Path.home() / ".local/share/argos/memory")
            ),
        )
        parser.add_argument("--mission-id", type=UUID, required=True)
        if command == "capture":
            parser.add_argument("--db", required=True)
            parser.add_argument("--journal", required=True)
        if command in {"capture", "focus"}:
            parser.add_argument("--review-id", type=UUID, required=True)
        if command == "info":
            parser.add_argument("--expected-head")
        if command == "search":
            parser.add_argument("--query", default="")
            parser.add_argument("--limit", type=int, default=20)
            parser.add_argument("--include-stale", action="store_true")
            parser.add_argument(
                "--origin",
                choices=(
                    "verified_archive",
                    "human_annotation",
                    "human_decision",
                    "llm_output",
                    "review_error",
                    "coverage_limit",
                ),
            )
        if command in {"get", "delete"}:
            parser.add_argument("--entry-id", required=True)
        if command == "delete":
            parser.add_argument(
                "--input", required=True, help="Private JSON with reason"
            )


def execute(args: argparse.Namespace) -> int:
    try:
        if args.action.startswith("review_memory_"):
            emit(_memory(args), structured=True)
            return 0
        if args.action.startswith("review_workflow_"):
            result = _workflow(args)
            emit(result, structured=True)
            return 1 if result["state"] in {"failed", "interrupted"} else 0
        if args.action == "review_analyze":
            result = asyncio.run(
                analyze_mission(
                    private_path(args.db),
                    args.mission_id,
                    OllamaProvider(args.model, args.ollama_port, args.timeout_seconds),
                    max_context_bytes=args.max_context_bytes,
                )
            )
            emit(result, structured=True)
            return 1 if result["status"] == "failed" else 0
        if args.action == "review_capabilities":
            registry = ToolRegistry.load(args.registry) if args.registry else None
            result = capability_registry(registry)
        elif args.action == "review_summary" and args.memory_root:
            if args.journal or args.expected_head:
                raise ValueError(
                    "Read journal checkpoints separately with memory enrichment"
                )
            result = review_with_memory(
                private_path(args.db),
                args.mission_id,
                args.memory_root,
                max_context_bytes=args.max_context_bytes,
                max_memory_bytes=args.max_memory_bytes,
                max_memory_items=args.max_memory_items,
                memory_query=args.memory_query,
            )
        elif args.action == "review_summary":
            result = mission_review(
                private_path(args.db),
                args.mission_id,
                max_context_bytes=args.max_context_bytes,
                journal=private_path(args.journal) if args.journal else None,
                expected_head=args.expected_head,
            )
        elif args.action == "review_journal_append":
            supplied = load_report_file(
                str(private_path(args.input)), max_bytes=MAX_INPUT_BYTES
            )
            archive = private_path(args.db)
            journal = private_path(args.journal, create=not Path(args.journal).exists())
            result = record_decision(archive, journal, args.mission_id, supplied)
        elif args.action == "review_journal_show":
            result = read_journal(
                private_path(args.journal),
                mission_id=args.mission_id,
                expected_head=args.expected_head,
            )
        else:
            result = mission_snapshot(private_path(args.db), args.mission_id)
    except (JournalIntegrityError, WebIntegrityError, sqlite3.Error):
        emit({"error": "review_integrity_or_storage_failed"}, structured=True)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        emit({"error": "review_invalid_input"}, structured=True)
        return 2
    emit(result, structured=True)
    return 0


def _workflow(args: argparse.Namespace) -> dict:
    command = args.action.removeprefix("review_workflow_")
    journal = private_path(
        args.journal, create=command == "start" and not Path(args.journal).exists()
    )
    if command == "start":
        result = create_workflow(private_path(args.db), journal, args.mission_id)
    elif command == "show":
        result = read_workflow(
            journal, args.review_id, expected_head=args.expected_head
        )
    elif command == "analyze":
        result = asyncio.run(
            analyze_workflow(
                private_path(args.db),
                journal,
                args.review_id,
                OllamaProvider(args.model, args.ollama_port, args.timeout_seconds),
            )
        )
    else:
        supplied = load_report_file(
            str(private_path(args.input)), max_bytes=MAX_INPUT_BYTES
        )
        if command == "accept":
            result = accept_workflow(
                private_path(args.db), journal, args.review_id, supplied
            )
        else:
            if set(supplied) != {"operator", "note"}:
                raise ValueError("Expected operator and note")
            handler = annotate_workflow if command == "annotate" else interrupt_workflow
            result = handler(
                journal, args.review_id, supplied["operator"], supplied["note"]
            )
    if not getattr(args, "history", False):
        result.pop("events")
    return result


def _memory(args: argparse.Namespace) -> dict:
    engine = MemoryEngine(args.memory_root, args.mission_id)
    command = args.action.removeprefix("review_memory_")
    if command == "capture":
        return engine.capture(
            private_path(args.db), private_path(args.journal), args.review_id
        )
    if command == "info":
        return engine.info(expected_head=args.expected_head)
    if command == "search":
        return engine.search(
            args.query,
            limit=args.limit,
            include_stale=args.include_stale,
            origin=args.origin,
        )
    if command == "get":
        return engine.get(args.entry_id)
    if command == "focus":
        return engine.focus(args.review_id)
    supplied = load_report_file(
        str(private_path(args.input)), max_bytes=MAX_INPUT_BYTES
    )
    if set(supplied) != {"reason"}:
        raise ValueError("Expected deletion reason")
    return engine.forget(args.entry_id, supplied["reason"])
