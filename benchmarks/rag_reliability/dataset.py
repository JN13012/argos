"""Frozen M3.5.6.1 corrective stress cases and limited development data."""

import json
from hashlib import sha256
from pathlib import Path

from benchmarks.rag_eval.dataset import ROOT as HISTORICAL_ROOT
from benchmarks.rag_eval.dataset import Case, Note

ROOT = Path(__file__).resolve().parent


def read(split: str) -> tuple[list[Note], list[Case]]:
    subset = json.loads((ROOT / "cases.json").read_text())[split]
    notes = [
        Note(key, "fixture", title, text, f"fixture:m3561:{key}", lifecycle)
        for key, title, text, lifecycle in subset["notes"]
    ]
    cases = [
        Case(key, group, expected, question, tuple(relevant), evidence)
        for key, group, expected, question, relevant, evidence in subset["cases"]
    ]
    return notes, cases


def fingerprints() -> dict[str, str]:
    inputs = {
        "cases": ROOT / "cases.json",
        "protocol": ROOT / "protocol.json",
        "historical_acceptance": HISTORICAL_ROOT / "protocol.json",
    }
    return {
        name: sha256(path.read_bytes()).hexdigest() for name, path in inputs.items()
    }
