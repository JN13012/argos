"""Explicit V2 attempt lifecycle on the existing supervised review event chain."""

import asyncio
import sqlite3
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from uuid import UUID

from argos.backend.attack.web.report_files import decode_json_object
from argos.backend.consultation.analyst import (
    GROUNDING_POLICY,
    InvalidSelection,
    Selector,
    analyze,
)
from argos.backend.consultation.context import Budget, fingerprint
from argos.backend.consultation.propositions import Proposition
from argos.backend.knowledge.contracts import KnowledgeIntegrityError
from argos.backend.knowledge.router import RetrievalMode

from .context_v2 import PreparedReview, Purpose, ReviewContextV2
from .journal import JournalIntegrityError, _hash
from .llm import LLMError
from .workflow import (
    MAX_RESTITUTION_BYTES,
    _append,
    _checked_history,
    _private_review_file,
    read_workflow,
)

CONTRACT = "consultative-analyst-v2"


async def analyze_workflow_v2(
    journal: Path,
    review_id: UUID,
    context: ReviewContextV2,
    objective: str,
    mode: RetrievalMode,
    budget: Budget,
    selector: Selector,
    *,
    propositions: tuple[Proposition, ...] = (),
) -> dict:
    _private_review_file(journal)
    saved = read_workflow(journal, review_id)
    if str(context.mission_id) != saved["mission_id"] or context.database is None:
        raise PermissionError("Context is outside the supervised review mission")
    _private_review_file(context.database)
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
            "contract": CONTRACT,
            "grounding_policy": GROUNDING_POLICY,
            "propositions_sha256": (
                fingerprint([asdict(proposition) for proposition in propositions])
                if propositions
                else None
            ),
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
            envelope,
            selector,
            model,
            lambda: context.validate(prepared.pins),
            propositions=propositions,
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
            "restitution_version": 1,
        }
    _append(
        journal,
        str(review_id),
        state,
        state,
        {
            "contract": CONTRACT,
            "attempt_sha256": started["sha256"],
            **outcome,
        },
        started["sha256"],
        restitution=reply,
    )
    result = read_workflow(journal, review_id)
    if reply is not None:
        result["consultation"] = reply
    return result


def read_restitution(
    journal: Path,
    review_id: UUID,
    context: ReviewContextV2,
    *,
    attempt_sha256: str | None = None,
    expected_head: str | None = None,
) -> dict:
    """Load a committed V2 response and revalidate its current reading scope."""
    if attempt_sha256 is not None:
        _hash(attempt_sha256)
    uri = _private_review_file(journal).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.execute("BEGIN")
        history, head = _checked_history(connection, review_id, expected_head)
        created = history[0]["data"]
        if str(context.mission_id) != created["mission_id"] or context.database is None:
            raise PermissionError("Context is outside the supervised review mission")
        _private_review_file(context.database)
        event = next(
            (
                entry
                for entry in reversed(history)
                if entry["kind"] == "ready"
                and entry["data"].get("contract") == CONTRACT
                and (
                    attempt_sha256 is None
                    or entry["data"].get("attempt_sha256") == attempt_sha256
                )
            ),
            None,
        )
        if event is None:
            return {"error": "no_completed_v2_attempt"}
        outcome = event["data"]
        if "restitution_version" not in outcome:
            return {"error": "historical_restitution_unavailable"}
        if outcome["restitution_version"] != 1:
            raise JournalIntegrityError("Unknown restitution format")
        row = connection.execute(
            "SELECT payload FROM review_restitutions "
            "WHERE event_sha256 = ? AND length(payload) <= ?",
            (event["sha256"], MAX_RESTITUTION_BYTES),
        ).fetchone()
        if row is None or not isinstance(row[0], bytes):
            raise JournalIntegrityError("Missing or invalid private restitution")
        try:
            reply = decode_json_object(row[0])
        except ValueError as error:
            raise JournalIntegrityError("Invalid private restitution") from error
        if fingerprint(reply) != outcome["response_sha256"]:
            raise JournalIntegrityError("Restitution fingerprint differs")
        attempt = next(
            (
                entry
                for entry in history
                if entry["sequence"] < event["sequence"]
                and entry["kind"] == "analyzing"
                and entry["sha256"] == outcome["attempt_sha256"]
                and entry["data"].get("contract") == CONTRACT
            ),
            None,
        )
        if (
            attempt is None
            or attempt["data"]["pins"]["snapshot"] != created["snapshot"]["sha256"]
            or reply.get("payload_sha256") != attempt["data"]["payload_sha256"]
        ):
            raise JournalIntegrityError("Restitution is outside the recorded attempt")
    context.validate(attempt["data"]["pins"])
    return {
        "review_id": str(review_id),
        "state": history[-1]["state"],
        "head_sha256": head,
        "attempt_sha256": outcome["attempt_sha256"],
        "response_sha256": outcome["response_sha256"],
        "consultation": reply,
    }


async def analyze_documentary(
    prepared: PreparedReview,
    context: ReviewContextV2,
    selector: Selector,
    *,
    propositions: tuple[Proposition, ...] = (),
) -> dict:
    model = await selector.identify()
    response = await analyze(
        prepared.envelope,
        selector,
        model,
        lambda: context.validate(prepared.pins),
        propositions=propositions,
    )
    response["timings_ms"].update(prepared.timings_ms)
    response["model"] = asdict(model)
    return response
