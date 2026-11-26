"""Operate on a single private documentary collection from the terminal."""

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from uuid import UUID

from .chunking import ChunkConfig, ChunkStrategy
from .contracts import (
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    Source,
    Tag,
)
from .documents import KnowledgeStore
from .loader import file_media_type
from .retrieval import (
    DEFAULT_RESULT_BYTES,
    LexicalWeights,
    SearchFilters,
    SQLiteKnowledgeRetriever,
)


def _parse_tag(raw: str) -> Tag:
    dimension, separator, value = raw.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("Expected DIMENSION=VALUE")
    try:
        return Tag(dimension, value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _chunk_arguments(parser: argparse.ArgumentParser) -> None:
    defaults = ChunkConfig()
    parser.add_argument(
        "--strategy",
        type=ChunkStrategy,
        choices=tuple(ChunkStrategy),
        default=defaults.strategy,
    )
    parser.add_argument("--size", type=int, default=defaults.size)
    parser.add_argument("--overlap", type=int, default=defaults.overlap)


def _search_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("query")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_RESULT_BYTES)
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--domain", action="append", default=[])
    parser.add_argument("--tag", type=_parse_tag, action="append", default=[])
    parser.add_argument("--declared-version")


def add_parser(commands: argparse._SubParsersAction) -> None:
    group = commands.add_parser("knowledge", help="Manage local documentary knowledge")
    group.add_argument(
        "--collection",
        type=CollectionKind,
        choices=tuple(CollectionKind),
        default=CollectionKind.USER,
    )
    group.add_argument("--scope-id", type=UUID, help="Mission or organization UUID")
    actions = group.add_subparsers(required=True)

    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        parser = actions.add_parser(name, help=help_text)
        parser.set_defaults(action=f"knowledge_{name}")
        return parser

    command("init", "Initialize or migrate the selected collection")
    source = command("source-register", "Register a source pending approval")
    source.add_argument("source")
    source.add_argument("--publisher", required=True)
    source.add_argument("--origin", required=True)
    source.add_argument("--rights", required=True)
    source.add_argument("--official", action="store_true")
    command("source-approve", "Approve a registered source").add_argument("source")
    command("source-withdraw", "Withdraw a registered source").add_argument("source")

    import_file = command("import", "Stage a local Markdown, TXT or JSON file")
    import_file.add_argument("path", type=Path)
    import_file.add_argument("--title", required=True)
    import_file.add_argument(
        "--origin", required=True, help="Stable provenance reference"
    )
    import_file.add_argument("--language")
    import_file.add_argument("--tag", action="append", type=_parse_tag, default=[])
    import_file.add_argument("--declared-version")
    _chunk_arguments(import_file)

    versions = command("versions", "List retained document versions")
    versions.add_argument("--limit", type=int, default=100)
    inspect = command(
        "inspect", "Inspect a retained version, including pending versions"
    )
    inspect.add_argument("--normalized", action="store_true")
    show = command("show", "Read the current approved version")
    show.add_argument("--normalized", action="store_true")
    fragments = command("fragments", "Read a page of fragments for a version")
    _chunk_arguments(fragments)
    fragments.add_argument("--offset", type=int, default=0, help="First ordinal")
    fragments.add_argument("--limit", type=int, default=100)
    fragments.add_argument(
        "--retained", action="store_true", help="Inspect unpublished or withdrawn data"
    )
    approve = command("approve", "Publish a staged version")
    withdraw = command("withdraw", "Withdraw a document")
    for parser in (import_file, versions, inspect, show, fragments, approve, withdraw):
        parser.add_argument("source")
        parser.add_argument("document")
    for parser in (inspect, fragments, approve):
        parser.add_argument("version")

    search = command("search", "Rank published fragments by BM25")
    _search_arguments(search)
    weights = LexicalWeights()
    search.add_argument("--title-weight", type=float, default=weights.title)
    search.add_argument("--body-weight", type=float, default=weights.body)
    _search_arguments(command("exact", "Find an exact technical or document reference"))
    command("index-status", "Count published versions and indexed search entries")
    command("index-verify", "Verify SQLite, FTS and published search projections")
    command("index-rebuild", "Rebuild the authorized collection's search indexes")


def _search_action(
    collection: Collection, action: str, args: argparse.Namespace
) -> object:
    weights = (
        LexicalWeights(args.title_weight, args.body_weight)
        if action == "search"
        else LexicalWeights()
    )
    # The local operator explicitly selects the collection for this invocation.
    engine = SQLiteKnowledgeRetriever(
        collection, allowed_collections=(collection,), weights=weights
    )
    match action:
        case "index-status":
            return asdict(engine.index_status())
        case "index-verify":
            return asdict(engine.verify_index())
        case "index-rebuild":
            return asdict(engine.rebuild_index())
    filters = SearchFilters(
        tuple(args.source),
        tuple(args.domain),
        tuple(args.tag),
        args.declared_version,
    )
    query = engine.retrieve if action == "search" else engine.exact
    return [
        asdict(hit)
        for hit in query(
            args.query,
            filters=filters,
            limit=args.limit,
            max_bytes=args.max_bytes,
        )
    ]


def _document_action(
    store: KnowledgeStore, action: str, args: argparse.Namespace
) -> object:
    ref = DocumentRef(args.source, args.document)
    match action:
        case "import":
            metadata = DocumentMetadata(
                args.title,
                file_media_type(args.path),
                args.origin,
                language=args.language,
                declared_version=args.declared_version,
                tags=tuple(args.tag),
            )
            config = ChunkConfig(args.strategy, args.size, args.overlap)
            return asdict(store.ingest_file(args.path, ref, metadata, config))
        case "versions":
            return [asdict(v) for v in store.versions(ref, limit=args.limit)]
        case "inspect":
            version = store.inspect_version(ref, args.version)
            result = asdict(version)
            if args.normalized:
                result["normalized"] = asdict(store.inspect_normalized(ref, version.id))
            return result
        case "show":
            version = store.current(ref)
            result = asdict(version)
            if args.normalized:
                result["normalized"] = asdict(store.read_normalized(ref, version.id))
            return result
        case "fragments":
            config = ChunkConfig(args.strategy, args.size, args.overlap)
            read = store.inspect_fragments if args.retained else store.read_fragments
            return [
                asdict(fragment)
                for fragment in read(
                    ref, args.version, config, offset=args.offset, limit=args.limit
                )
            ]
        case "approve":
            return asdict(store.approve_version(ref, args.version))
        case "withdraw":
            store.withdraw_document(ref)
            return {"status": "withdrawn"}
    raise ValueError("Unknown knowledge action")


def execute(args: argparse.Namespace) -> int:
    try:
        collection = Collection(args.collection, args.scope_id)
        action = args.action.removeprefix("knowledge_")
        if action in ("search", "exact") or action.startswith("index-"):
            output = _search_action(collection, action, args)
        else:
            store = KnowledgeStore(collection)
            match action:
                case "init":
                    store.initialize()
                    output = {"status": "initialized"}
                case "source-register":
                    output = asdict(
                        store.sources.register(
                            Source(
                                args.source,
                                args.publisher,
                                args.origin,
                                args.rights,
                                args.official,
                            )
                        )
                    )
                case "source-approve":
                    output = asdict(store.sources.approve(args.source))
                case "source-withdraw":
                    output = asdict(store.sources.withdraw(args.source))
                case _:
                    output = _document_action(store, action, args)
        # Escape control characters from documentary data in terminal output.
        print(json.dumps(output, default=str))
        return 0
    except (KeyError, OSError, ValueError, sqlite3.Error) as error:
        print(f"Error: {str(error).splitlines()[0]}", file=sys.stderr)
        return 1
