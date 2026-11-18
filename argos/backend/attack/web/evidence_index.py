"""Portable index of receipt references from a verified web report projection."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from .contracts import _digest, _instant
from .receipts import ERRORS, FINAL_STATES, WebIntegrityError, digest

if TYPE_CHECKING:
    from .store import WebStore


def evidence_index(report: dict) -> dict:
    receipts: dict[str, dict] = {}

    def add(item: dict, fingerprint: str | None, kind: str, owner_id: str) -> None:
        if fingerprint is None:
            return  # A request without a stored receipt does not count as evidence.
        _digest(fingerprint)
        request_id = str(UUID(item["request_id"]))
        reference = dict(kind=kind, id=str(UUID(owner_id)))
        receipt = receipts.setdefault(
            request_id, dict(request_id=request_id, sha256=fingerprint, references=[])
        )
        if receipt["sha256"] != fingerprint:
            raise WebIntegrityError("Conflicting receipt fingerprints")
        if reference not in receipt["references"]:
            receipt["references"].append(reference)

    for route in report["surface"]:
        add(route, route.get("evidence_sha256"), "route", route["id"])
    for navigation in report["browser"]["navigation_details"]:
        for resource in navigation["resources"]:
            add(
                resource,
                resource["receipt_sha256"],
                "navigation",
                navigation["navigation_id"],
            )
    for check in report["redirect_checks"]:
        for step in check["steps"]:
            add(step, step["receipt_sha256"], "redirect_check", check["id"])

    configuration = report["configuration_sha256"]
    _digest(configuration)
    ordered = [receipts[request_id] for request_id in sorted(receipts)]
    for receipt in ordered:
        receipt["references"].sort(key=lambda item: (item["kind"], item["id"]))
    return dict(
        schema_version=1,
        mission_id=str(UUID(report["mission_id"])),
        run_id=str(UUID(report["run_id"])),
        configuration_sha256=configuration,
        receipts=ordered,
    )


def evidence_detail(
    store: WebStore, report: dict, request_id: UUID, expected_sha256: str | None
) -> dict:
    index = evidence_index(report)
    ref = next(
        (item for item in index["receipts"] if item["request_id"] == str(request_id)),
        None,
    )
    if ref is None:
        raise ValueError("Request is not in the execution evidence index")
    if expected_sha256 is not None:
        _digest(expected_sha256)
        if ref["sha256"] != expected_sha256:
            raise WebIntegrityError("Receipt does not match the supplied fingerprint")
    receipt = store.evidence(request_id)
    if receipt is None or digest(receipt) != ref["sha256"]:
        raise WebIntegrityError("Receipt does not match the evidence index")

    state, error = receipt["state"], receipt["error"]
    if state not in FINAL_STATES or error is not None and error not in ERRORS:
        raise WebIntegrityError("Invalid receipt state")
    recorded = datetime.fromisoformat(receipt["recorded_at"])
    _instant(recorded)
    response = receipt["response"]
    result = None
    if response is not None:
        status, complete = response["status"], response["body_complete"]
        if (
            status is not None
            and (type(status) is not int or not 200 <= status <= 599)
            or type(complete) is not bool
        ):
            raise WebIntegrityError("Invalid receipt response summary")
        result = dict(status=status, body_complete=complete)
    return dict(
        schema_version=index["schema_version"],
        mission_id=index["mission_id"],
        run_id=index["run_id"],
        **ref,
        recorded_at=recorded.isoformat(),
        state=state,
        error=error,
        response=result,
    )
