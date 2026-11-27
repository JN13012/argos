"""Versioned private SQLite storage scoped to the effective Unix identity."""

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import AbstractContextManager, closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from argos.data_paths import data_path, prepare_area

from .contracts import (
    DEFAULT_DOMAINS,
    MAX_ORIGINAL_BYTES,
    Collection,
    CollectionKind,
    KnowledgeIntegrityError,
    identifier,
)

SCHEMA_VERSION = 6
APPLICATION_ID = 0x4152474B  # ARGK
_SCHEMA_V1 = (
    """CREATE TABLE collection (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        uid INTEGER NOT NULL, kind TEXT NOT NULL, scope_id TEXT NOT NULL
    )""",
    "CREATE TABLE domain (id TEXT PRIMARY KEY) WITHOUT ROWID",
    """CREATE TABLE source (
        id TEXT PRIMARY KEY, publisher TEXT NOT NULL, origin TEXT NOT NULL,
        rights TEXT NOT NULL, official INTEGER NOT NULL CHECK (official IN (0, 1)),
        registered_at TEXT NOT NULL,
        approved_at TEXT, withdrawn_at TEXT
    ) WITHOUT ROWID""",
    """CREATE TABLE document (
        source_id TEXT REFERENCES source(id), id TEXT NOT NULL, withdrawn_at TEXT,
        PRIMARY KEY (source_id, id)
    ) WITHOUT ROWID""",
    f"""CREATE TABLE original (
        sha256 TEXT PRIMARY KEY, content BLOB NOT NULL,
        CHECK (typeof(content) = 'blob'
               AND length(content) BETWEEN 1 AND {MAX_ORIGINAL_BYTES})
    ) WITHOUT ROWID""",
    """CREATE TABLE version (
        id TEXT PRIMARY KEY, source_id TEXT NOT NULL, document_id TEXT NOT NULL,
        original_sha256 TEXT NOT NULL REFERENCES original(sha256),
        metadata_json TEXT NOT NULL, imported_at TEXT NOT NULL, approved_at TEXT,
        superseded_at TEXT,
        FOREIGN KEY (source_id, document_id) REFERENCES document(source_id, id),
        CHECK (superseded_at IS NULL OR approved_at IS NOT NULL)
    ) WITHOUT ROWID""",
    """CREATE INDEX version_document ON version(source_id, document_id)""",
    """CREATE UNIQUE INDEX version_current ON version(source_id, document_id)
       WHERE approved_at IS NOT NULL AND superseded_at IS NULL""",
)

_SCHEMA_V2 = (
    """CREATE TABLE normalized (
        sha256 TEXT PRIMARY KEY, content TEXT NOT NULL
    ) WITHOUT ROWID""",
    """CREATE TABLE normalization (
        original_sha256 TEXT NOT NULL REFERENCES original(sha256),
        media_type TEXT NOT NULL, normalizer TEXT NOT NULL,
        normalized_sha256 TEXT NOT NULL REFERENCES normalized(sha256),
        PRIMARY KEY (original_sha256, media_type, normalizer)
    ) WITHOUT ROWID""",
    """CREATE TABLE chunk_set (
        id TEXT PRIMARY KEY,
        normalized_sha256 TEXT NOT NULL REFERENCES normalized(sha256),
        chunker TEXT NOT NULL,
        fragment_count INTEGER NOT NULL CHECK (fragment_count > 0),
        UNIQUE (normalized_sha256, chunker)
    ) WITHOUT ROWID""",
    """CREATE TABLE fragment (
        chunk_set_id TEXT NOT NULL REFERENCES chunk_set(id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        start INTEGER NOT NULL CHECK (start >= 0),
        end INTEGER NOT NULL CHECK (end > start),
        sha256 TEXT NOT NULL,
        PRIMARY KEY (chunk_set_id, ordinal)
    ) WITHOUT ROWID""",
    """CREATE TABLE version_projection (
        version_id TEXT NOT NULL REFERENCES version(id),
        chunk_set_id TEXT NOT NULL REFERENCES chunk_set(id),
        PRIMARY KEY (version_id, chunk_set_id)
    ) WITHOUT ROWID""",
)

_SCHEMA_V6 = (
    """CREATE TABLE maintenance_feed (
        source_id TEXT PRIMARY KEY REFERENCES source(id), binding TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL, release TEXT NOT NULL, sequence INTEGER NOT NULL,
        checked_at TEXT NOT NULL, review_days INTEGER NOT NULL
    ) WITHOUT ROWID""",
    """CREATE TABLE maintenance_item (
        source_id TEXT NOT NULL REFERENCES maintenance_feed(source_id),
        document_id TEXT NOT NULL, entry_sha256 TEXT NOT NULL,
        version_id TEXT NOT NULL REFERENCES version(id),
        state TEXT NOT NULL CHECK(state IN ('current', 'removed', 'obsolete')),
        PRIMARY KEY (source_id, document_id),
        FOREIGN KEY (source_id, document_id) REFERENCES document(source_id, id)
    ) WITHOUT ROWID""",
    """CREATE TABLE maintenance_run (
        source_id TEXT NOT NULL REFERENCES maintenance_feed(source_id),
        sequence INTEGER NOT NULL, release TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
        checked_at TEXT NOT NULL, counts_json TEXT NOT NULL,
        PRIMARY KEY (source_id, sequence)
    ) WITHOUT ROWID""",
    """CREATE INDEX maintenance_run_release ON maintenance_run(source_id, release)""",
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def _private(path: Path, uid: int, *, directory: bool) -> None:
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(info.st_mode)
        or info.st_uid != uid
        or info.st_mode & 0o077
        or (not directory and info.st_nlink != 1)
    ):
        raise PermissionError("Knowledge storage must be private and owned by this UID")


class CollectionDatabase:
    def __init__(self, collection: Collection):
        if type(collection) is not Collection:
            raise TypeError("Expected a validated collection")
        if collection.kind is CollectionKind.ORGANIZATION:
            raise PermissionError("Organizational sharing is unavailable")
        self.uid = os.geteuid()
        scope = str(collection.scope_id) if collection.scope_id is not None else ""
        self.identity = (self.uid, collection.kind.value, scope)
        area = data_path("knowledge")
        suffix = f"-{scope}" if scope else ""
        self._directories = (
            area.parent,
            area,
            area / f"uid-{self.uid}",
            area / f"uid-{self.uid}" / f"{collection.kind.value}{suffix}",
        )
        self.path = self._directories[-1] / "knowledge.sqlite3"

    def _check_uid(self) -> None:
        if os.geteuid() != self.uid:
            raise PermissionError("Knowledge storage identity changed")

    def _check_ancestors(self) -> None:
        # A user namespace can display the mounted root owner under another UID.
        trusted_owners = {0, self.uid, Path("/").stat().st_uid}
        for parent in self._directories[0].parents:
            try:
                info = parent.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in trusted_owners
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)
            ):
                raise PermissionError("Knowledge data root has an untrusted ancestor")

    def _check_paths(self) -> None:
        self._check_uid()
        self._check_ancestors()
        if self.path.parent.resolve() != self.path.parent:
            raise PermissionError("Symlinked knowledge paths are unavailable")
        for path in self._directories:
            _private(path, self.uid, directory=True)
        _private(self.path, self.uid, directory=False)
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                _private(Path(str(self.path) + suffix), self.uid, directory=False)
            except FileNotFoundError:
                continue

    def initialize(self) -> None:
        self._check_uid()
        if data_path("knowledge") != self._directories[1]:
            raise ValueError("Data root changed since the collection was bound")
        self._check_ancestors()
        prepare_area("knowledge")
        for directory in self._directories[2:]:
            directory.mkdir(mode=0o700, exist_ok=True)
            _private(directory, self.uid, directory=True)
        try:
            descriptor = os.open(
                self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        with self._transaction(write=True, initialize=True):
            pass

    def _check_schema(self, db: sqlite3.Connection, *, initialize: bool) -> None:
        application = db.execute("PRAGMA application_id").fetchone()[0]
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if initialize and (application, version) == (0, 0):
            if db.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone():
                raise KnowledgeIntegrityError(
                    "Refusing to initialize an unrelated database"
                )
            for statement in _SCHEMA_V1:
                db.execute(statement)
            db.execute("INSERT INTO collection VALUES (1, ?, ?, ?)", self.identity)
            db.executemany(
                "INSERT INTO domain VALUES (?)", [(d,) for d in DEFAULT_DOMAINS]
            )
            db.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            application, version = APPLICATION_ID, 1
        if application != APPLICATION_ID or not (
            version == SCHEMA_VERSION or (initialize and 1 <= version < SCHEMA_VERSION)
        ):
            raise KnowledgeIntegrityError("Unsupported knowledge database schema")
        row = db.execute(
            "SELECT uid, kind, scope_id FROM collection WHERE singleton = 1"
        ).fetchone()
        if row is None or tuple(row) != self.identity:
            raise KnowledgeIntegrityError("Knowledge collection identity differs")
        if version == 1:
            for statement in _SCHEMA_V2:
                db.execute(statement)
            version = 2
        if version == 2:
            from .search_index import SCHEMA_V3, populate

            for statement in SCHEMA_V3:
                db.execute(statement)
            populate(db)
            version = 3
        if version == 3:
            from .vector_index import SCHEMA_V4

            for statement in SCHEMA_V4:
                db.execute(statement)
            version = 4
        if version == 4:
            from .vector_generation import SCHEMA_V5

            for statement in SCHEMA_V5:
                db.execute(statement)
            version = 5
        if version == 5:
            for statement in _SCHEMA_V6:
                db.execute(statement)
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @contextmanager
    def _transaction(
        self, *, write: bool, initialize: bool = False
    ) -> Iterator[sqlite3.Connection]:
        self._check_paths()
        mode = "rw" if write else "ro"
        with closing(
            sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True)
        ) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA trusted_schema = OFF")
            with db:
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                self._check_schema(db, initialize=initialize)
                yield db

    def read(self) -> AbstractContextManager[sqlite3.Connection]:
        return self._transaction(write=False)

    def write(self) -> AbstractContextManager[sqlite3.Connection]:
        return self._transaction(write=True)

    def list_domains(self) -> tuple[str, ...]:
        with self.read() as db:
            return tuple(
                row[0] for row in db.execute("SELECT id FROM domain ORDER BY id")
            )

    def register_domain(self, domain_id: str) -> None:
        with self.write() as db:
            db.execute(
                "INSERT OR IGNORE INTO domain VALUES (?)", (identifier(domain_id),)
            )
