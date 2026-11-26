"""Explicit V2 attempt lifecycle on the existing supervised review event chain."""

import asyncio
import sqlite3
from dataclasses import asdict
from pathlib import Path
from uuid import UUID

from argos.backend.consultation.analyst import (
    GROUNDING_POLICY,
    InvalidSelection,
    Selector,
    analyze,
)
from argos.backend.consultation.context import Budget, fingerprint
from argos.backend.knowledge.contracts import KnowledgeIntegrityError
from argos.backend.knowledge.router import RetrievalMode

from .context_v2 import PreparedReview, Purpose, ReviewContextV2
from .journal import JournalIntegrityError
from .llm import LLMError
from .workflow import _append, read_workflow


async def analyze_workflow_v2(
    journal: Path,
    review_id: UUID,
    context: ReviewContextV2,
    objective: str,
    mode: RetrievalMode,
    budget: Budget,
    selector: Selector,
) -> dict:
    saved = read_workflow(journal, review_id)
    if str(context.mission_id) != saved["mission_id"]:
        raise PermissionError("Context is outside the supervised review mission")
    model = await selector.identify()
    if budget.window > model.max_window:
        raise InvalidSelection("Context window exceeds the installed model limit")
    prepared = context.prepare(
        objective,
        Purpose.ARCHIVE,
        mode,
        budget,
        selector.size,
        expected_snapshot=saved["snapshot_sha256"],
    )
    envelope = prepared.envelope
    started = _append(
        journal,
        str(review_id),
        "analyzing",
        "analyzing",
        {
            "contract": "consultative-analyst-v2",
            "grounding_policy": GROUNDING_POLICY,
            "configuration": {"model": asdict(model), "budget": asdict(budget)},
            "pins": prepared.pins,
            "units": [
                {
                    "kind": unit.kind,
                    "component": unit.component,
                    "pin": unit.pin,
                    "text_sha256": fingerprint(unit.text),
                }
                for unit in envelope.units
            ],
            "payload_sha256": fingerprint(envelope.data_json),
            "input_token_bound": envelope.input_bound,
            "prompt_bytes": envelope.prompt_bytes,
        },
        saved["review_head_sha256"],
    )
    reply = None
    try:
        reply = await analyze(
            envelope, selector, model, lambda: context.validate(prepared.pins)
        )
        reply["timings_ms"].update(prepared.timings_ms)
    except (asyncio.CancelledError, KeyboardInterrupt):
        current = read_workflow(journal, review_id)
        if current["review_head_sha256"] == started["sha256"]:
            _append(
                journal,
                str(review_id),
                "interrupted",
                "interrupted",
                {"reason": "inference_interrupted"},
                started["sha256"],
            )
        raise
    except LLMError as error:
        failure = error.code.value
    except InvalidSelection:
        failure = "invalid_selection"
    except (KnowledgeIntegrityError, JournalIntegrityError, PermissionError, KeyError):
        failure = "stale_or_inadmissible_context"
    except (sqlite3.Error, OSError):
        failure = "context_storage_failed"
    except Exception:
        failure = "unexpected_consultation_error"

    if reply is None:
        state = "failed"
        outcome = {"error": failure}
    else:
        state = "ready"
        outcome = {
            "abstention": reply["abstention"],
            "grounding": reply["grounding"],
            "usage": reply["usage"],
            "timings_ms": reply["timings_ms"],
            "selected_ids": [item["id"] for item in reply["claims"]],
            "contradiction_ids": [item["id"] for item in reply["contradictions"]],
            "uncertainty_ids": [item["id"] for item in reply["uncertainties"]],
            "response_sha256": fingerprint(reply),
        }
    _append(
        journal,
        str(review_id),
        state,
        state,
        {
            "contract": "consultative-analyst-v2",
            "attempt_sha256": started["sha256"],
            **outcome,
        },
        started["sha256"],
    )
    result = read_workflow(journal, review_id)
    if reply is not None:
        result["consultation"] = reply
    return result


async def analyze_documentary(
    prepared: PreparedReview, context: ReviewContextV2, selector: Selector
) -> dict:
    model = await selector.identify()
    response = await analyze(
        prepared.envelope, selector, model, lambda: context.validate(prepared.pins)
    )
    response["timings_ms"].update(prepared.timings_ms)
    response["model"] = asdict(model)
    return response
