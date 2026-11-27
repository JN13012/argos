"""Replay historical false abstentions with exact transmitted and reference contexts."""

import argparse
import asyncio
import json
from pathlib import Path

from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.consultation.context import Budget, encode
from benchmarks.rag_eval.resources import stop_processes
from benchmarks.rag_eval.run import DIGEST, generate
from benchmarks.rag_reliability.dataset import read
from benchmarks.rag_reliability.run import usage
from benchmarks.retrieval.consultation_probe import launch, wait


async def replay(source: Path, output: Path, port: int) -> None:
    cases = {case.id: case for case in read("final")[1]}
    previous = {}
    for path in source.glob("*-qwen3-embedding.jsonl"):
        previous[path.name.split("-")[0]] = {
            row["case"]: row for row in map(json.loads, path.read_text().splitlines())
        }

    selector = OllamaSelector(OllamaProvider("qwen3:4b", port), DIGEST)
    model = await selector.identify()
    budget = Budget(reserve=96)
    async with selector._client() as client:
        with output.open("x") as stream:
            for key, case in cases.items():
                old = previous["after"][key]
                if case.expected == "u" or old["verdict"] != "u":
                    continue
                packet = json.loads(old["payload"])
                gold = set(case.relevant)
                if case.evidence:
                    gold.add("archive")
                allowed = {
                    item["id"]
                    for item in packet["items"]
                    if old["available"][str(item["id"])] in gold
                }
                if not gold <= set(old["available"].values()):
                    raise ValueError(f"Reference context lacks gold input for {key}")
                reference = dict(packet)
                reference["items"] = [
                    {**item, "id": index}
                    for index, item in enumerate(
                        (item for item in packet["items"] if item["id"] in allowed), 1
                    )
                ]
                pair = {}
                for label, context in (
                    ("transmitted", packet),
                    ("reference", reference),
                ):
                    text = old["payload"] if label == "transmitted" else encode(context)
                    result = await generate(client, model, budget, text, keep_alive=120)
                    verdict, refs, counts = usage(
                        result, budget, len(text.encode()) + 512
                    )
                    pair[label] = {
                        "verdict": verdict,
                        "references": refs,
                        "tokens": counts,
                        "raw": result,
                        "context": context,
                    }
                reply = old["raw"]
                stream.write(
                    json.dumps(
                        {
                            "case": key,
                            "expected": case.expected,
                            "group": case.group,
                            "reference_ids_transmitted": sorted(allowed),
                            "historical_binary": previous["before"][key]["verdict"],
                            "old_policy_reasons": reply["grounding"]["reasons"],
                            "old_selected_gold": bool(set(old["references"]) & allowed),
                            "controls": pair,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                stream.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=11545)
    parser.add_argument("--ollama", type=Path, default=Path("data/ollama").resolve())
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, parents=True)
    process = launch(args.out, args.ollama, args.port, "diagnosis", "generator")
    try:
        wait(args.port)
        asyncio.run(replay(args.source, args.out / "controls.jsonl", args.port))
    finally:
        stop_processes([process])


if __name__ == "__main__":
    main()
