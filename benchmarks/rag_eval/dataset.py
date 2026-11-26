"""Frozen, locally authored notes and judgements for M3.5.6."""

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLISHERS = {
    "owasp": (
        "OWASP",
        "https://cheatsheetseries.owasp.org/cheatsheets/",
        "CC BY-SA 4.0",
    ),
    "cwe": ("MITRE CWE", "https://cwe.mitre.org/data/definitions/", "CWE Terms of Use"),
    "ietf": ("RFC Editor", "https://www.rfc-editor.org/rfc/", "Individual RFC notice"),
    "mdn": (
        "MDN Web Docs",
        "https://developer.mozilla.org/en-US/docs/",
        "CC BY-SA 2.5",
    ),
    "anssi": (
        "ANSSI",
        "https://messervices.cyber.gouv.fr/documents-guides/",
        "Licence Ouverte 2.0",
    ),
    "fixture": ("M3.5.6 fixtures", "fixture:m356:", "Original synthetic fixture"),
}


@dataclass(frozen=True)
class Note:
    id: str
    source: str
    title: str
    text: str
    origin: str
    lifecycle: str = ""


@dataclass(frozen=True)
class Case:
    id: str
    group: str
    expected: str
    question: str
    relevant: tuple[str, ...]
    evidence: str = ""


def load(split: str) -> tuple[list[Note], list[Case]]:
    if split not in {"development", "final"}:
        raise ValueError("Expected development or final")
    notes, cases = [], []
    for line in (ROOT / "notes.tsv").read_text().splitlines():
        ident, source, url, title, text, *questions = line.split("|")
        if ident.startswith("dev-") != (split == "development"):
            continue
        notes.append(Note(ident, source, title, text, PUBLISHERS[source][1] + url))
        group = "remediation" if source in {"owasp", "anssi"} else "knowledge"
        for number, item in enumerate(questions, 1):
            answer, question = item.split(":", 1)
            cases.append(Case(f"{ident}-{number}", group, answer, question, (ident,)))
    if split == "final":
        special = json.loads((ROOT / "special.json").read_text())
        for ident, title, text, lifecycle in special["notes"]:
            notes.append(
                Note(ident, "fixture", title, text, f"fixture:{ident}", lifecycle)
            )
        for ident, group, answer, question, relevant, evidence in special["cases"]:
            cases.append(
                Case(ident, group, answer, question, tuple(relevant), evidence)
            )
    return notes, cases


def frozen_inputs() -> dict[str, str]:
    return {
        name: sha256((ROOT / name).read_bytes()).hexdigest()
        for name in ("notes.tsv", "special.json", "protocol.json")
    }
