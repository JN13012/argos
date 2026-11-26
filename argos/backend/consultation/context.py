"""Bounded, data-only context shared by consultative specializations."""

import json
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from time import perf_counter


def encode(value: object) -> str:
    # Escaping '<' also prevents literal Qwen chat control tokens in the data.
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).replace("<", r"\u003c")


def fingerprint(value: object) -> str:
    return sha256(encode(value).encode()).hexdigest()


class UnitKind(StrEnum):
    CONTRADICTION = "contradiction"
    UNCERTAINTY = "uncertainty"
    OBSERVATION = "observation"
    INFERENCE = "inference"
    PASSAGE = "passage"


class Component(StrEnum):
    ARCHIVE = "archive"
    MEMORY = "memory"
    KNOWLEDGE = "knowledge"


@dataclass(frozen=True, slots=True)
class Unit:
    kind: UnitKind
    component: Component
    text: str
    # Canonical serialized reference (kept out of the prompt).
    pin: str


@dataclass(frozen=True, slots=True)
class Budget:
    window: int = 8192
    reserve: int = 384
    max_bytes: int = 32768
    max_items: int = 48
    passage_chars: int = 1200

    def __post_init__(self) -> None:
        for value, low, high in (
            (self.window, 2048, 131072),
            (self.reserve, 64, self.window // 2),
            (self.max_bytes, 1024, 131072),
            (self.max_items, 1, 128),
            (self.passage_chars, 64, 8000),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Invalid consultation budget")


@dataclass(frozen=True, slots=True)
class Envelope:
    data_json: str
    units: tuple[Unit, ...]
    input_bound: int
    prompt_bytes: int
    budget: Budget
    assembly_ms: float


# Providers expose the actual framed prompt size and its token bound.
PromptSizer = Callable[[str], tuple[int, int]]


def assemble(
    purpose: str,
    objective: str,
    units: Iterable[Unit],
    budget: Budget,
    size: PromptSizer,
    *,
    coverage: dict,
    upstream_omissions: dict[str, int] | None = None,
) -> Envelope:
    started = perf_counter()
    if not objective or len(objective.encode()) > 1024:
        raise ValueError("Invalid consultation objective")
    # Round robin within a priority tier gives complementary components room
    # to contribute while letting one component use spare room in the others.
    tiers = {
        UnitKind.CONTRADICTION: 0,
        UnitKind.UNCERTAINTY: 0,
        UnitKind.OBSERVATION: 1,
        UnitKind.PASSAGE: 1,
        UnitKind.INFERENCE: 2,
    }
    queues: dict[int, dict[Component, deque[Unit]]] = defaultdict(
        lambda: defaultdict(deque)
    )
    seen: set[tuple] = set()
    omitted = Counter(upstream_omissions or {})
    duplicates: Counter[str] = Counter()
    for unit in units:
        key = (
            (unit.kind, unit.pin)
            if unit.kind is UnitKind.PASSAGE
            else (unit.kind, unit.text)
        )
        if key in seen:
            duplicates[unit.component] += 1
            continue
        seen.add(key)
        queues[tiers[unit.kind]][unit.component].append(unit)
        omitted[unit.component] += 1

    selected: list[Unit] = []
    rows: list[dict] = []
    data = {
        "version": "consultative-context-v2",
        "purpose": purpose,
        "objective": objective,
        "coverage": coverage,
        "omitted": omitted,
        "duplicates": duplicates,
        "items": rows,
    }
    for tier in sorted(queues):
        by_component = queues[tier]
        while any(by_component.values()) and len(rows) < budget.max_items:
            for queue in by_component.values():
                if not queue or len(rows) == budget.max_items:
                    continue
                unit = queue.popleft()
                excerpt = unit.text
                if unit.kind is UnitKind.PASSAGE:
                    excerpt = excerpt[: budget.passage_chars]
                rows.append(
                    {
                        "id": len(rows) + 1,
                        "kind": unit.kind,
                        "component": unit.component,
                        "text": excerpt,
                        "excerpt": excerpt != unit.text,
                    }
                )
                omitted[unit.component] -= 1
                byte_count, token_bound = size(encode(data))
                if (
                    byte_count > budget.max_bytes
                    or token_bound > budget.window - budget.reserve
                ):
                    rows.pop()
                    omitted[unit.component] += 1
                    continue
                selected.append(Unit(unit.kind, unit.component, excerpt, unit.pin))
    payload = encode(data)
    byte_count, token_bound = size(payload)
    if byte_count > budget.max_bytes or token_bound > budget.window - budget.reserve:
        raise ValueError("Consultation header exceeds its budget")
    return Envelope(
        payload,
        tuple(selected),
        token_bound,
        byte_count,
        budget,
        (perf_counter() - started) * 1000,
    )
