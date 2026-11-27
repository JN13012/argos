"""Operate on a single private documentary collection from the terminal."""

import argparse
import json
import sqlite3
import sys
from contextlib import nullcontext
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
from .embeddings import (
    DEFAULT_BATCH,
    OLLAMA_PROFILES,
    EmbeddingProviderError,
    OllamaEmbeddingProvider,
)
from .loader import file_media_type
from .maintenance import Maintenance
from .obsidian import scan
from .retrieval import (
    DEFAULT_RESULT_BYTES,
    LexicalWeights,
    SearchFilters,
    SQLiteKnowledgeRetriever,
)
from .router import RetrievalMode, RetrievalRouter
from .synchronization import LocalManifestProvider, PublicSynchronization
from .vector_retrieval import CosineCalibration, NumPyKnowledgeRetriever


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


def _embedding_arguments(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--model", choices=tuple(OLLAMA_PROFILES), required=required)
    parser.add_argument("--model-digest", help="Expected digest from Ollama /api/tags")
    parser.add_argument("--runtime-version", default="0.40.18")
    parser.add_argument("--port", type=int, default=11536)
    parser.add_argument("--dimensions", type=int)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--keep-alive", type=int, default=60)


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
    command("source-show", "Inspect a registered source").add_argument("source")
    sources = command("source-list", "List sources and approval status")
    sources.add_argument("--limit", type=int, default=100)
    sources.add_argument("--after")
    report = command("maintenance-report", "Inspect freshness and maintenance history")
    report.add_argument("source")
    report.add_argument("--limit", type=int, default=20)

    obsidian = command(
        "obsidian-import", "Review or apply an explicit private selection"
    )
    obsidian.add_argument("--root", required=True, type=Path)
    obsidian.add_argument("--select", required=True, action="append")
    obsidian.add_argument("--exclude", action="append", default=[])
    public = command("sync-public", "Review or apply a simulated public release")
    public.add_argument("--manifest", type=Path, required=True)
    public.add_argument("--release", help="Explicitly pinned upstream release")
    for parser in (obsidian, public):
        parser.add_argument("source")
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Preview, the default")
        mode.add_argument(
            "--apply", metavar="PLAN_SHA256", help="Apply a reviewed plan"
        )
        parser.add_argument("--review-days", type=int)
        parser.add_argument("--remove-missing", action="store_true")
        _embedding_arguments(parser, required=False)

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

    retrieval = command("retrieve", "Route exact, lexical or dense documentary search")
    _search_arguments(retrieval)
    _embedding_arguments(retrieval, required=False)
    retrieval.add_argument(
        "--mode",
        type=RetrievalMode,
        choices=tuple(RetrievalMode),
        default=RetrievalMode.AUTO,
    )
    retrieval.add_argument("--minimum-cosine", type=float)
    retrieval.add_argument("--calibration-corpus")
    for name, help_text in (
        ("vector-build", "Resume incremental embedding of published fragments"),
        ("vector-status", "Inspect current coverage for an embedding space"),
        ("vector-cache", "Inspect the collection-local embedding cache"),
        ("vector-verify", "Verify cached Float32 vectors and live membership"),
        ("vector-rebuild", "Rebuild vector membership from the cache"),
        ("vector-unload", "Unload the selected local embedding model"),
    ):
        parser = command(name, help_text)
        _embedding_arguments(parser, required=True)
        if name == "vector-rebuild":
            parser.add_argument("--discard-cache", action="store_true")


def _filters(args: argparse.Namespace) -> SearchFilters:
    return SearchFilters(
        tuple(args.source),
        tuple(args.domain),
        tuple(args.tag),
        args.declared_version,
    )


def _provider(args: argparse.Namespace) -> OllamaEmbeddingProvider:
    return OllamaEmbeddingProvider(
        args.model,
        port=args.port,
        runtime=args.runtime_version,
        digest=args.model_digest,
        dimensions=args.dimensions,
        batch_size=args.batch_size,
        timeout=args.timeout,
        keep_alive=args.keep_alive,
    )


def _maintenance_action(
    collection: Collection, action: str, args: argparse.Namespace
) -> dict:
    maintenance = Maintenance(collection)
    if action == "maintenance-report":
        return maintenance.report(args.source, limit=args.limit)
    review = {"review_days": args.review_days, "remove_missing": args.remove_missing}
    provider = _provider(args) if args.apply and args.model else None
    if action == "obsidian-import":
        if collection.kind is not CollectionKind.USER:
            raise PermissionError("Obsidian requires the private user collection")
        snapshot = scan(
            args.root, args.source, tuple(args.select), exclusions=tuple(args.exclude)
        )
        manifest = snapshot.manifest
        if args.apply:
            with provider or nullcontext() as embedding:
                return maintenance.apply(
                    manifest, args.apply, snapshot.fetch, embedding=embedding, **review
                )
        plan = maintenance.preview(manifest, **review)
    else:
        if args.apply and not args.release:
            raise ValueError("Applying a public release requires --release")
        synchronization = PublicSynchronization(
            collection, LocalManifestProvider(args.manifest)
        )
        if args.apply:
            with provider or nullcontext() as embedding:
                return synchronization.apply(
                    args.source, args.release, args.apply, embedding=embedding, **review
                )
        manifest, plan = synchronization.preview(
            args.source, release=args.release, **review
        )
    return {
        "dry_run": True,
        "plan": {**asdict(plan), "sha256": plan.identity},
        "entries": [asdict(entry) for entry in manifest.entries],
    }


def _routed_action(collection: Collection, args: argparse.Namespace) -> dict:
    allowed = (collection,)
    sql = SQLiteKnowledgeRetriever(collection, allowed_collections=allowed)

    def search(dense: NumPyKnowledgeRetriever | None = None) -> dict:
        result = RetrievalRouter(sql, dense).search(
            args.query,
            mode=args.mode,
            filters=_filters(args),
            limit=args.limit,
            max_bytes=args.max_bytes,
        )
        return asdict(result)

    if args.mode in (RetrievalMode.EXACT, RetrievalMode.LEXICAL):
        return search()
    calibrated = args.minimum_cosine is not None
    if calibrated != bool(args.calibration_corpus) or calibrated and args.model is None:
        raise ValueError("A cosine threshold requires a corpus identity and a model")
    if args.model is None:
        return search()
    with _provider(args) as provider:
        calibration = (
            CosineCalibration(
                provider.space.identity, args.calibration_corpus, args.minimum_cosine
            )
            if calibrated
            else None
        )
        return search(
            NumPyKnowledgeRetriever(
                collection,
                allowed_collections=allowed,
                provider=provider,
                calibration=calibration,
            )
        )


def _vector_action(
    collection: Collection, action: str, args: argparse.Namespace
) -> dict:
    with _provider(args) as provider:
        if action == "vector-unload":
            provider.unload()
            return {"status": "unloaded", "space": asdict(provider.space)}
        dense = NumPyKnowledgeRetriever(
            collection,
            allowed_collections=(collection,),
            provider=provider,
        )
        match action:
            case "vector-status":
                status = dense.vector_status()
            case "vector-cache":
                status = dense.vector_status()
                return {
                    "space": asdict(status.space),
                    "entries": status.cache_entries,
                    "bytes": status.cache_bytes,
                }
            case "vector-verify":
                status = dense.verify_vectors()
            case "vector-build" | "vector-rebuild":
                report = (
                    dense.build_vectors()
                    if action == "vector-build"
                    else dense.rebuild_vectors(discard_cache=args.discard_cache)
                )
                result = asdict(report)
                result["status"]["ready"] = report.status.ready
                return result
            case _:
                raise ValueError("Unknown vector action")
        return asdict(status) | {"ready": status.ready}


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
    query = engine.retrieve if action == "search" else engine.exact
    return [
        asdict(hit)
        for hit in query(
            args.query,
            filters=_filters(args),
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
        if action == "retrieve":
            output = _routed_action(collection, args)
        elif action.startswith("vector-"):
            output = _vector_action(collection, action, args)
        elif action in ("search", "exact") or action.startswith("index-"):
            output = _search_action(collection, action, args)
        elif action in ("maintenance-report", "obsidian-import", "sync-public"):
            output = _maintenance_action(collection, action, args)
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
                case "source-show":
                    output = asdict(store.sources.get(args.source))
                case "source-list":
                    output = [
                        asdict(record)
                        for record in store.sources.list(
                            limit=args.limit, after=args.after
                        )
                    ]
                case _:
                    output = _document_action(store, action, args)
        # Escape control characters from documentary data in terminal output.
        print(json.dumps(output, default=str))
        return 0
    except (
        KeyError,
        OSError,
        ValueError,
        sqlite3.Error,
        EmbeddingProviderError,
    ) as error:
        print(f"Error: {str(error).splitlines()[0]}", file=sys.stderr)
        return 1
