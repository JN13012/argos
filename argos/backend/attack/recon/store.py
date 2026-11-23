"""Private, hashed pipeline snapshots. No automatic replay after interruption."""

import json
import sqlite3
from pathlib import Path
from uuid import UUID

from argos.backend.attack.web.receipts import WebIntegrityError, canonical, digest


class ReconStore:
    def __init__(self, path, *, readonly=False):
        self.db = sqlite3.connect(
            Path(path).absolute().as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
            uri=True,
        )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def initialize(self):
        with self.db:
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS recon_runs "
                "(id TEXT PRIMARY KEY, payload TEXT NOT NULL, sha256 TEXT NOT NULL)"
            )

    def save(self, value):
        with self.db:
            self.db.execute(
                "INSERT INTO recon_runs VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "payload=excluded.payload, sha256=excluded.sha256",
                (value["id"], canonical(value), digest(value)),
            )

    def get(self, run_id: UUID):
        row = self.db.execute(
            "SELECT payload,sha256 FROM recon_runs WHERE id=?", (str(run_id),)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown recon run")
        try:
            value = json.loads(row[0])
            if digest(value) != row[1] or value["id"] != str(run_id):
                raise ValueError
            return value
        except (ValueError, KeyError, TypeError) as error:
            raise WebIntegrityError("Recon snapshot differs") from error

    def reconcile(self):
        for row in self.db.execute("SELECT id FROM recon_runs").fetchall():
            value = self.get(UUID(row[0]))
            if value["status"] == "running":
                value.update(status="interrupted", reason="runtime_lost")
                for stage in value["stages"]:
                    if stage["state"] == "running":
                        stage.update(state="interrupted", reason="runtime_lost")
                self.save(value)
