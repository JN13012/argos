"""Portable index of receipt references from a verified web report projection."""

from uuid import UUID

from .contracts import _digest
from .receipts import WebIntegrityError


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
