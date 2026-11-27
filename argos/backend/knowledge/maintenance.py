"""Plan and atomically publish bounded snapshots of approved documentary sources."""

import json
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from . import projections, vector_index
from .chunking import ChunkConfig
from .contracts import (
    MAX_ORIGINAL_BYTES,
    Approval,
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeConflictError,
    KnowledgeIntegrityError,
    Tag,
    bounded_text,
    identifier,
    sha256_id,
)
from .documents import _approve, _import_identity, _json, _stage, _withdraw
from .embeddings import EmbeddingProvider
from .registry import source_record
from .storage import CollectionDatabase, now

MAX_ENTRIES = 512
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
_CHUNKS = ChunkConfig()
_OBSOLETE = Tag("lifecycle", "obsolete")


def digest(value: object) -> str:
    return sha256(_json(value).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Entry:
    id: str
    metadata: DocumentMetadata
    sha256: str
    size: int

    def __post_init__(self) -> None:
        identifier(self.id)
        sha256_id(self.sha256)
        if type(self.metadata) is not DocumentMetadata:
            raise TypeError("Expected validated entry metadata")
        if type(self.size) is not int or not 1 <= self.size <= MAX_ORIGINAL_BYTES:
            raise ValueError("Invalid manifest document size")

    @property
    def identity(self) -> str:
        return digest(asdict(self))


@dataclass(frozen=True, slots=True)
class Manifest:
    source_id: str
    kind: str
    scope: str
    release: str
    entries: tuple[Entry, ...]

    def __post_init__(self) -> None:
        identifier(self.source_id)
        if self.kind not in {"obsidian", "public"}:
            raise ValueError("Invalid maintenance provider kind")
        sha256_id(self.scope)
        bounded_text(self.release, "release", limit=128)
        if type(self.entries) is not tuple or len(self.entries) > MAX_ENTRIES:
            raise ValueError("Manifest exceeds document limit")
        if any(type(entry) is not Entry for entry in self.entries):
            raise TypeError("Expected validated manifest entries")
        ordered = tuple(sorted(self.entries, key=lambda entry: entry.id))
        if len({entry.id for entry in ordered}) != len(ordered):
            raise ValueError("Duplicate document in manifest")
        if sum(entry.size for entry in ordered) > MAX_SNAPSHOT_BYTES:
            raise ValueError("Manifest exceeds total byte limit")
        object.__setattr__(self, "entries", ordered)

    @property
    def identity(self) -> str:
        return digest(asdict(self))

    @property
    def binding(self) -> str:
        return digest((self.kind, self.scope))


@dataclass(frozen=True, slots=True)
class Change:
    id: str
    action: str
    prior_version: str | None
    sha256: str | None


@dataclass(frozen=True, slots=True)
class Plan:
    source: str
    release: str
    manifest_sha256: str
    base_sequence: int
    review_days: int
    remove_missing: bool
    changes: tuple[Change, ...]

    @property
    def identity(self) -> str:
        return digest(asdict(self))


def _review_days(days: int) -> int:
    if type(days) is not int or not 1 <= days <= 3650:
        raise ValueError("Expected a revision cadence of 1 to 3650 days")
    return days


def _plan(
    db: sqlite3.Connection,
    manifest: Manifest,
    review_days: int | None,
    remove_missing: bool,
) -> Plan:
    source = manifest.source_id
    registered = source_record(db, source)
    if registered.status is not Approval.APPROVED:
        raise KnowledgeConflictError("Maintenance requires an approved source")
    feed = db.execute(
        "SELECT * FROM maintenance_feed WHERE source_id = ?", (source,)
    ).fetchone()
    if feed is not None and feed["binding"] != manifest.binding:
        raise KnowledgeConflictError(
            "Source already belongs to another maintenance scope"
        )
    if manifest.kind == "public":
        if manifest.scope != digest(
            (registered.source.origin, registered.source.rights)
        ):
            raise KnowledgeConflictError("Manifest scope differs from approved source")
        seen = db.execute(
            "SELECT manifest_sha256 FROM maintenance_run "
            "WHERE source_id = ? AND release = ?",
            (source, manifest.release),
        ).fetchone()
        if seen and (
            seen[0] != manifest.identity
            or feed is None
            or feed["release"] != manifest.release
        ):
            raise KnowledgeConflictError("Public release is changed or superseded")
    tracked = {
        row["document_id"]: row
        for row in db.execute(
            """SELECT m.*, d.withdrawn_at, v.id AS live_version
               FROM maintenance_item m
               JOIN document d ON (d.source_id, d.id) = (m.source_id, m.document_id)
               LEFT JOIN version v ON (v.source_id, v.document_id) = (d.source_id, d.id)
                   AND v.approved_at IS NOT NULL AND v.superseded_at IS NULL
               WHERE m.source_id = ? ORDER BY m.document_id""",
            (source,),
        )
    }
    for state in tracked.values():
        if state["state"] == "current" and state["live_version"] != state["version_id"]:
            raise KnowledgeConflictError(
                "Managed document was changed outside maintenance"
            )
    selected = {entry.id: entry for entry in manifest.entries}
    changes = []
    for key, entry in selected.items():
        prior = tracked.get(key)
        obsolete = _OBSOLETE in entry.metadata.tags
        if prior is None:
            if db.execute(
                "SELECT 1 FROM document WHERE source_id = ? AND id = ?", (source, key)
            ).fetchone():
                raise KnowledgeConflictError(
                    "Manifest collides with an unmanaged document"
                )
            action = "obsolete" if obsolete else "new"
        elif prior["state"] == "current" and prior["withdrawn_at"]:
            action = "operator_withdrawn"
        elif prior["entry_sha256"] == entry.identity and (
            (prior["state"] == "obsolete" and obsolete) or prior["state"] == "current"
        ):
            action = "unchanged"
        elif prior["state"] != "current":
            raise KnowledgeConflictError(
                "Manifest tries to republish a retired document ID"
            )
        else:
            action = "obsolete" if obsolete else "modified"
        changes.append(
            Change(key, action, prior["version_id"] if prior else None, entry.sha256)
        )
    for key in sorted(tracked.keys() - selected.keys()):
        prior = tracked[key]
        if prior["state"] == "current" and not prior["withdrawn_at"]:
            action = "removed" if remove_missing else "missing"
            changes.append(Change(key, action, prior["version_id"], None))
    days = _review_days(
        review_days if review_days is not None else feed["review_days"] if feed else 30
    )
    return Plan(
        source,
        manifest.release,
        manifest.identity,
        feed["sequence"] if feed else 0,
        days,
        remove_missing,
        tuple(changes),
    )


class Maintenance:
    def __init__(self, collection: Collection):
        self.collection = collection
        self._database = CollectionDatabase(collection)

    def preview(
        self,
        manifest: Manifest,
        *,
        review_days: int | None = None,
        remove_missing: bool = False,
    ) -> Plan:
        if (
            manifest.kind == "obsidian"
            and self.collection.kind is not CollectionKind.USER
        ):
            raise PermissionError("Obsidian requires the private user collection")
        with self._database.read() as db:
            return _plan(db, manifest, review_days, remove_missing)

    def apply(
        self,
        manifest: Manifest,
        expected: str,
        fetch: Callable[[Entry], bytes],
        *,
        review_days: int | None = None,
        remove_missing: bool = False,
        embedding: EmbeddingProvider | None = None,
    ) -> dict:
        plan = self.preview(
            manifest, review_days=review_days, remove_missing=remove_missing
        )
        if sha256_id(expected) != plan.identity:
            raise KnowledgeConflictError(
                "Maintenance preview changed; inspect it again"
            )
        sequence = plan.base_sequence + 1
        entries = {entry.id: entry for entry in manifest.entries}
        prepared = {}
        for change in plan.changes:
            if change.action not in {"new", "modified", "obsolete"}:
                continue
            entry = entries[change.id]
            original = fetch(entry)
            if (
                type(original) is not bytes
                or len(original) != entry.size
                or sha256(original).hexdigest() != entry.sha256
            ):
                raise KnowledgeIntegrityError(
                    f"Body does not match manifest: {entry.id}"
                )
            declared = (
                f"obsidian-{sequence}"
                if manifest.kind == "obsidian"
                else manifest.release
            )
            metadata = replace(entry.metadata, declared_version=declared)
            original_sha, encoded = _import_identity(metadata, original)
            projection = projections.prepare(
                self._database, original, original_sha, metadata.media_type, _CHUNKS
            )
            prepared[change.id] = (
                entry,
                metadata,
                original,
                original_sha,
                encoded,
                projection,
            )
        counts = Counter(change.action for change in plan.changes)
        checked_at = now()
        published = []
        with self._database.write() as db:
            if _plan(db, manifest, review_days, remove_missing) != plan:
                raise KnowledgeConflictError(
                    "Maintenance state changed during preparation"
                )
            db.execute(
                """INSERT INTO maintenance_feed VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET
                   manifest_sha256=excluded.manifest_sha256,
                   release=excluded.release, sequence=excluded.sequence,
                   checked_at=excluded.checked_at, review_days=excluded.review_days""",
                (
                    plan.source,
                    manifest.binding,
                    plan.manifest_sha256,
                    plan.release,
                    sequence,
                    checked_at,
                    plan.review_days,
                ),
            )
            for change in plan.changes:
                document = DocumentRef(plan.source, change.id)
                if change.action == "removed":
                    _withdraw(db, document)
                    db.execute(
                        "UPDATE maintenance_item SET state = 'removed' "
                        "WHERE source_id = ? AND document_id = ?",
                        (plan.source, change.id),
                    )
                elif change.id in prepared:
                    entry, metadata, original, original_sha, encoded, projection = (
                        prepared[change.id]
                    )
                    version = _stage(
                        db, document, metadata, original, original_sha, encoded
                    )
                    projections.persist(db, version, _CHUNKS, projection)
                    state = "obsolete" if change.action == "obsolete" else "current"
                    if state == "current":
                        _approve(db, document, version.id)
                        published.append(version.id)
                    else:
                        _withdraw(db, document)
                    db.execute(
                        """INSERT INTO maintenance_item VALUES (?, ?, ?, ?, ?)
                           ON CONFLICT(source_id,document_id) DO UPDATE SET
                           entry_sha256=excluded.entry_sha256,
                           version_id=excluded.version_id,
                           state=excluded.state""",
                        (plan.source, change.id, entry.identity, version.id, state),
                    )
            attached = (
                vector_index.refresh_versions(db, embedding, tuple(published))
                if embedding is not None
                else 0
            )
            db.execute(
                "INSERT INTO maintenance_run VALUES (?, ?, ?, ?, ?, ?)",
                (
                    plan.source,
                    sequence,
                    plan.release,
                    plan.manifest_sha256,
                    checked_at,
                    _json(counts),
                ),
            )
        return {
            "plan": plan.identity,
            "sequence": sequence,
            "checked_at": checked_at,
            "counts": dict(counts),
            "vectors_attached": attached,
        }

    def report(self, source: str, *, limit: int = 20) -> dict:
        identifier(source)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Expected report limit of 1 to 100")
        with self._database.read() as db:
            record = source_record(db, source)
            row = db.execute(
                "SELECT * FROM maintenance_feed WHERE source_id = ?", (source,)
            ).fetchone()
            if row is None:
                return {
                    "source": source,
                    "approval": record.status,
                    "freshness": "untracked",
                    "runs": [],
                }
            runs = [
                {
                    "sequence": item[0],
                    "release": item[1],
                    "manifest_sha256": item[2],
                    "checked_at": item[3],
                    "counts": json.loads(item[4]),
                }
                for item in db.execute(
                    """SELECT sequence,release,manifest_sha256,checked_at,counts_json
                       FROM maintenance_run WHERE source_id = ?
                       ORDER BY sequence DESC LIMIT ?""",
                    (source, limit),
                )
            ]
        due = datetime.fromisoformat(row["checked_at"]) + timedelta(
            days=row["review_days"]
        )
        freshness = "review_due" if datetime.now(UTC) >= due else "reviewed"
        if record.status is Approval.WITHDRAWN:
            freshness = "withdrawn"
        elif runs and runs[0]["counts"].get("missing"):
            freshness = "incomplete"
        return {
            "source": source,
            "approval": record.status,
            "release": row["release"],
            "checked_at": row["checked_at"],
            "review_days": row["review_days"],
            "due_at": due.isoformat(),
            "freshness": freshness,
            "runs": runs,
        }
