"""Deterministic checks of bounded, caller-supplied consultative propositions."""

import json
from dataclasses import dataclass
from enum import StrEnum

from .context import Component, Unit, UnitKind


class PropositionStatus(StrEnum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    INSUFFICIENT = "insufficient"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True, slots=True)
class Attribution:
    """Verbatim occurrence in a complete, admissible documentary passage."""

    text: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.text, str)
            or not self.text.strip()
            or len(self.text.encode()) > 1024
        ):
            raise ValueError("Invalid attribution text")


@dataclass(frozen=True, slots=True)
class RecordedHTTPStatus:
    """The status recorded by one identified archive receipt."""

    receipt_id: str
    status: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.receipt_id, str)
            or not self.receipt_id
            or len(self.receipt_id.encode()) > 128
            or any(ch.isspace() for ch in self.receipt_id)
            or type(self.status) is not int
            or not 100 <= self.status <= 599
        ):
            raise ValueError("Invalid archived HTTP status proposition")


type Proposition = Attribution | RecordedHTTPStatus


def _literal(units: tuple[Unit, ...], text: str) -> tuple[PropositionStatus, list[int]]:
    matches, disputed = [], []
    for index, unit in enumerate(units, 1):
        if (
            unit.component is Component.KNOWLEDGE
            and not unit.truncated
            and unit.text == text
        ):
            if unit.kind is UnitKind.PASSAGE:
                matches.append(index)
            elif unit.kind is UnitKind.CONTRADICTION:
                disputed.append(index)
    if disputed:
        return PropositionStatus.UNDETERMINED, (disputed[:4] + matches[:4])
    if matches:
        return PropositionStatus.SUPPORTED, matches[:8]
    return PropositionStatus.INSUFFICIENT, []


def _http_record(
    units: tuple[Unit, ...], proposition: RecordedHTTPStatus
) -> tuple[PropositionStatus, list[int]]:
    readings: dict[int, list[int]] = {}
    for index, unit in enumerate(units, 1):
        if (
            unit.component not in {Component.ARCHIVE, Component.MEMORY}
            or unit.kind is not UnitKind.OBSERVATION
            or unit.truncated
        ):
            continue
        origin = json.loads(unit.pin).get("observation", {})
        if (
            origin.get("kind") != "http_receipt"
            or origin.get("id") != proposition.receipt_id
        ):
            continue
        record = json.loads(unit.text)
        status = record.get("status")
        if (
            record.get("kind") != "archived_http_response"
            or record.get("state") != "fact"
            or type(status) is not int
            or not 100 <= status <= 599
        ):
            continue
        readings.setdefault(status, []).append(index)
    if not readings:
        return PropositionStatus.INSUFFICIENT, []
    if len(readings) > 1:
        return PropositionStatus.UNDETERMINED, [refs[0] for refs in readings.values()][
            :8
        ]
    status, refs = next(iter(readings.items()))
    result = (
        PropositionStatus.SUPPORTED
        if status == proposition.status
        else PropositionStatus.CONTRADICTED
    )
    return result, refs[:8]


def evaluate(
    units: tuple[Unit, ...], propositions: tuple[Proposition, ...]
) -> list[dict]:
    """Evaluate only against already checked units of the same bounded envelope."""
    if len(propositions) > 8:
        raise ValueError("At most eight propositions per consultation")
    results = []
    for index, proposition in enumerate(propositions, 1):
        if isinstance(proposition, Attribution):
            scope = "verbatim_attribution_only"
            status, refs = _literal(units, proposition.text)
        elif isinstance(proposition, RecordedHTTPStatus):
            scope = "archived_record_only"
            status, refs = _http_record(units, proposition)
        else:
            raise TypeError("Unsupported consultation proposition")
        results.append(
            {
                "id": index,
                "status": status,
                "support_scope": scope,
                "references": [
                    {"id": ref, "citation": json.loads(units[ref - 1].pin)}
                    for ref in refs
                ],
            }
        )
    return results
