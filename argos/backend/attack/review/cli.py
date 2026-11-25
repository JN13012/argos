"""CLI for offline review of private mission records."""

import argparse
import sqlite3
from uuid import UUID

from argos.backend.attack.web.cli import emit, private_path
from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.core.tool_registry import ToolRegistry

from .capabilities import capability_registry
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


def execute(args: argparse.Namespace) -> int:
    try:
        if args.action == "review_capabilities":
            registry = ToolRegistry.load(args.registry) if args.registry else None
            result = capability_registry(registry)
        else:
            result = mission_snapshot(private_path(args.db), args.mission_id)
    except (WebIntegrityError, sqlite3.Error):
        emit({"error": "review_integrity_or_storage_failed"}, structured=True)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        emit({"error": "review_invalid_input"}, structured=True)
        return 2
    emit(result, structured=True)
    return 0
