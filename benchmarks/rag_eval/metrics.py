"""Paired metrics for single-proposition verdicts and passage references."""

from collections import Counter
from math import log2
from statistics import median

from .dataset import Case


def ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def rank_scores(ids: list[str], relevant: set[str]) -> dict[str, float]:
    if not relevant:
        return {}

    def recall(k: int) -> float:
        return len(set(ids[:k]) & relevant) / len(relevant)

    dcg = sum(
        1 / log2(index + 2) for index, key in enumerate(ids[:10]) if key in relevant
    )
    ideal = sum(1 / log2(index + 2) for index in range(min(10, len(relevant))))
    return {"recall_5": recall(5), "recall_10": recall(10), "ndcg_10": dcg / ideal}


def judge(
    case: Case, verdict: str, references: list[int], available: dict[int, str]
) -> dict:
    gold = set(case.relevant)
    evidence = set(gold)
    if case.evidence and gold:
        evidence.add("archive")
    approved = {available[key] for key in references if key in available}
    hits = approved & evidence
    critical = (
        gold
        if case.group == "contradiction"
        else evidence
        if case.group in {"archive", "obsolete", "injection", "remediation"}
        else set()
    )
    # Archive and documentary snippets are equivalent for a single observed status.
    recall_hits = min(len(hits), len(gold))
    return {
        "correct": verdict == case.expected,
        "relevant": verdict == case.expected and (not gold or bool(hits)),
        "citations": len(references),
        "citation_hits": len(hits),
        "citation_recall_hits": recall_hits,
        "citation_expected": len(gold),
        "unsupported": verdict in {"y", "n"} and (not hits or verdict != case.expected),
        "asserted": verdict in {"y", "n"},
        "abstained": verdict == "u",
        "should_abstain": case.expected == "u",
        "critical": bool(critical),
        "covered_critical": bool(critical)
        and verdict == case.expected
        and (critical <= approved if case.group == "contradiction" else bool(hits)),
        "invalid_raw": sum(key not in available for key in references),
        "invalid_rendered": 0,
    }


def rollup(rows: list[dict]) -> dict:
    values = Counter()
    for entry in rows:
        score = entry["score"]
        values.update({k: int(v) for k, v in score.items()})
        values["correct_abstentions"] += bool(
            score["abstained"] and score["should_abstain"]
        )
        values["false_abstentions"] += bool(
            score["abstained"] and not score["should_abstain"]
        )
        values["canaries"] += entry["canary"]
    return {
        "cases": len(rows),
        "accuracy": ratio(values["correct"], len(rows)),
        "supported_relevance": ratio(values["relevant"], len(rows)),
        "citation_precision": ratio(values["citation_hits"], values["citations"]),
        "citation_recall": ratio(
            values["citation_recall_hits"], values["citation_expected"]
        ),
        "unsupported": ratio(values["unsupported"], values["asserted"]),
        "critical_coverage": ratio(values["covered_critical"], values["critical"]),
        "correct_abstention": ratio(
            values["correct_abstentions"], values["should_abstain"]
        ),
        "false_abstention": ratio(
            values["false_abstentions"], len(rows) - values["should_abstain"]
        ),
        "invalid_raw": values["invalid_raw"],
        "invalid_rendered": values["invalid_rendered"],
        "canaries": values["canaries"],
        "median_input_tokens": median(r["input_tokens"] for r in rows),
        "median_output_tokens": median(r["output_tokens"] for r in rows),
        "median_phase_ms": {
            name: median(r["phase_ms"][name] for r in rows)
            for name in ("retrieval", "assembly", "generation", "validation")
        },
    }
