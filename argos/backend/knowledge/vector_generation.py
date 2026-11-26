"""SQLite snapshot markers for collection-local vector views."""

import sqlite3

from .contracts import KnowledgeIntegrityError


def _trigger(table: str, event: str, reset: str) -> str:
    action, _, fields = event.partition(" OF ")
    name = action.lower() + ("_metadata" if fields else "")
    return f"""CREATE TRIGGER vector_generation_{table}_{name}
        AFTER {event} ON {table} BEGIN
          UPDATE vector_generation SET revision = randomblob(16) {reset} WHERE id = 1;
        END"""


SCHEMA_V5 = (
    """CREATE TABLE vector_generation (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        revision BLOB NOT NULL CHECK(length(revision) = 16),
        validation BLOB NOT NULL CHECK(length(validation) = 16)
    )""",
    "INSERT INTO vector_generation VALUES (1, randomblob(16), randomblob(16))",
    """CREATE TABLE vector_member_identity (
        id INTEGER PRIMARY KEY REFERENCES search_fragment(id) ON DELETE CASCADE,
        token BLOB NOT NULL CHECK(length(token) = 16)
    )""",
    "INSERT INTO vector_member_identity SELECT id, randomblob(16) FROM search_fragment",
    """CREATE TRIGGER vector_generation_member_insert AFTER INSERT ON search_fragment
        BEGIN
          INSERT INTO vector_member_identity VALUES (new.id, randomblob(16));
        END""",
    *(
        _trigger(table, event, reset)
        for table, events, reset in (
            ("vector_link", ("INSERT", "UPDATE", "DELETE"), ""),
            ("vector_space", ("UPDATE", "DELETE"), ", validation = randomblob(16)"),
            ("vector_cache", ("UPDATE", "DELETE"), ", validation = randomblob(16)"),
            ("search_fragment", ("UPDATE",), ", validation = randomblob(16)"),
            ("vector_member_identity", ("UPDATE",), ", validation = randomblob(16)"),
            ("vector_member_identity", ("DELETE",), ""),
            ("search_document", ("UPDATE",), ", validation = randomblob(16)"),
            ("version", ("UPDATE",), ""),
            (
                "version",
                ("UPDATE OF metadata_json, id, document_id, source_id",),
                ", validation = randomblob(16)",
            ),
            ("source", ("UPDATE",), ""),
            ("document", ("UPDATE",), ""),
            ("chunk_set", ("UPDATE", "DELETE"), ", validation = randomblob(16)"),
            ("fragment", ("UPDATE", "DELETE"), ", validation = randomblob(16)"),
            (
                "version_projection",
                ("UPDATE", "DELETE"),
                ", validation = randomblob(16)",
            ),
        )
        for event in events
    ),
)


def generation(db: sqlite3.Connection) -> tuple[bytes, bytes]:
    row = db.execute(
        "SELECT revision, validation FROM vector_generation WHERE id = 1"
    ).fetchone()
    if row is None or any(
        type(value) is not bytes or len(value) != 16 for value in row
    ):
        raise KnowledgeIntegrityError("Invalid vector generation")
    return row[0], row[1]
