"""Hold retrieval fixed while probing selection of the exact archived packet."""

import json

from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.consultation.analyst import _refs
from argos.backend.consultation.context import Budget, encode, fingerprint

from .reference import EXPECTED_DOCS


async def probe(
    lab: str, packet: dict, pins: list[dict], selector: OllamaSelector, budget: Budget
) -> dict:
    candidates = []
    for item, unit in zip(packet["items"], pins, strict=True):
        pin = json.loads(unit["pin"])
        document = pin.get("reference", {}).get("document", {}).get("document_id")
        candidates.append((item, document))
    relevant = EXPECTED_DOCS[lab]
    documents = [pair for pair in candidates if pair[0]["kind"] == "passage"]
    others = [pair for pair in candidates if pair[0]["kind"] != "passage"]
    model = await selector.identify()
    outcomes = {}
    for name, objective, pairs in (
        ("repeat", packet["objective"], candidates),
        (
            "goal",
            "Citer les statuts HTTP attestés et les définitions documentaires utiles.",
            candidates,
        ),
        ("passages_first", packet["objective"], documents + others),
        ("passages_only", packet["objective"], documents),
    ):
        data = encode(
            {
                **packet,
                "objective": objective,
                "items": [
                    {**item, "id": index} for index, (item, _) in enumerate(pairs, 1)
                ],
            }
        )
        size, bound = selector.size(data)
        if size > budget.max_bytes or bound > budget.window - budget.reserve:
            outcomes[name] = {"status": "budget_exceeded", "input_bound": bound}
            continue
        selection = await selector.select(data, budget, model)
        refs = _refs(selection.content, len(pairs))
        selected_kinds = [pairs[index - 1][0]["kind"] for index in refs]
        selected_documents = {pairs[index - 1][1] for index in refs}
        outcomes[name] = {
            "status": "valid_selection",
            "packet_sha256": fingerprint(data),
            "input_bound": bound,
            "input_tokens": selection.input_tokens,
            "output_tokens": selection.output_tokens,
            "selected_kinds": selected_kinds,
            "selected_relevant_documents": sorted(selected_documents & relevant),
        }
    return outcomes
