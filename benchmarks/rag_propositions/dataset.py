"""Frozen independently authored proposition benchmark fixtures."""

import json
from hashlib import sha256
from pathlib import Path

from benchmarks.rag_eval.dataset import ROOT as LEGACY_ROOT
from benchmarks.rag_eval.dataset import Case, Note

ROOT = Path(__file__).resolve().parent


def read(split: str) -> tuple[list[Note], list[tuple[Case, list | None]]]:
    data = json.loads((ROOT / "cases.json").read_text())[split]
    notes = [
        Note(key, "fixture", title, text, f"fixture:m3562:{key}", life)
        for key, title, text, life in data["notes"]
    ]
    rows = []
    for key, group, expected, question, ids, *receipt in data["cases"]:
        record = receipt[0] if receipt else None
        case = Case(
            key,
            group,
            expected,
            question,
            tuple(ids),
            "verified synthetic receipt" if record and record[1] is not None else "",
        )
        rows.append((case, record))
    return notes, rows


def digests() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT.parent)): sha256(path.read_bytes()).hexdigest()
        for path in (
            ROOT / "cases.json",
            ROOT / "protocol.json",
            LEGACY_ROOT / "protocol.json",
        )
    }
