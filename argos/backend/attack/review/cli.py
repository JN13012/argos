"""CLI for offline review of private mission records."""

import argparse
import sqlite3
from pathlib import Path
from uuid import UUID

from argos.backend.attack.web.cli import emit, private_path
from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.attack.web.report_files import load_report_file
from argos.backend.core.tool_registry import ToolRegistry

from .capabilities import capability_registry
from .journal import (
    MAX_INPUT_BYTES,
    JournalIntegrityError,
    read_journal,
    record_decision,
)
from .snapshot import mission_snapshot


def add_parser(commands: argparse._SubParsersAction) -> None:
    group = commands.add_parser("review", help="Offline mission review")
    actions = group.add_subparsers(required=True)
    snapshot = actions.add_parser("snapshot", help="Read an archived mission snapshot")
    snapshot.set_defaults(action="review_snapshot")
    snapshot.add_argument("--db", required=True)
    snapshot.add_argument("--mission-id", type=UUID, required=True)
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


def execute(args: argparse.Namespace) -> int:
    try:
        if args.action == "review_capabilities":
            registry = ToolRegistry.load(args.registry) if args.registry else None
            result = capability_registry(registry)
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
