"""Attribute historical A4 failures to observable pipeline boundaries."""

import argparse
import json
from collections import Counter
from pathlib import Path

from benchmarks.rag_eval.dataset import Case, load


def classify(row: dict, case: Case, ranked: list[str]) -> list[str]:
    labels = []
    gold = set(case.relevant)
    available = set(row["available"].values())
    expected = gold - available
    archive_sufficient = case.group == "archive" and "archive" in available
    if gold and not archive_sufficient:
        if expected - set(ranked):
            labels.append("retrieval_missing")
        if expected & set(ranked):
            labels.append("context_selection_loss")
    if row["score"]["invalid_raw"]:
        labels.append("invalid_citation_caught")
    if row["score"]["citations"] > row["score"]["citation_hits"]:
        labels.append("citation_not_relevant")
    if row["score"]["unsupported"]:
        labels.append("unsupported_assertion")
    if case.expected == "u" and row["verdict"] in ("y", "n"):
        labels.append("missing_abstention")
    if case.group == "contradiction" and row["verdict"] != "u":
        labels.append("contradiction_ignored")
    if (
        row["verdict"] in ("y", "n")
        and not row["score"]["correct"]
        and ((gold and not expected) or archive_sufficient)
    ):
        labels.append("wrong_interpretation_despite_context")
    if case.group == "injection" and (row["canary"] or not row["score"]["correct"]):
        labels.append("injection_case_failure_cause_unproven")
    if row["canary"]:
        labels.append("raw_canary")
    return labels


def audit(source: Path) -> dict:
    _, annotated = load("final")
    cases = {case.id: case for case in annotated}
    ranks = json.loads((source / "qwen3-embedding-rankings.json").read_text())
    result = {}
    for line in (source / "generative.jsonl").read_text().splitlines():
        row = json.loads(line)
        if row["arm"] != "A4":
            continue
        key = row["case"]
        if key in result:
            raise ValueError("Duplicate historical A4 case")
        result[key] = classify(row, cases[key], ranks[key]["ids"])
    if result.keys() != cases.keys():
        raise ValueError("Incomplete historical A4 run")
    return {
        "cases": len(result),
        "counts": Counter(key for labels in result.values() for key in labels),
        "labels": result,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    result = json.dumps(audit(args.source), indent=2, sort_keys=True) + "\n"
    if args.out is None:
        print(result, end="")
    else:
        with args.out.open("x") as stream:
            stream.write(result)


if __name__ == "__main__":
    main()
