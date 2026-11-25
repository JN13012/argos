"""Compact, evidence-linked review of a frozen mission archive."""

from collections import Counter
from pathlib import Path
from uuid import UUID

from argos.backend.attack.recon.fingerprint_signals import CATALOG
from argos.backend.attack.web.receipts import canonical

from .capabilities import capability_registry
from .journal import read_journal
from .snapshot import mission_snapshot

VERSION = "mission-review-context-v1"
DEFAULT_CONTEXT_BYTES = 32_768
_CONTEXT_ORDER = ("contradiction", "unknown", "inference", "fact")
_MAP_STATES = {
    "observed": "fact",
    "inferred": "inference",
    "unknown": "unknown",
    "contradictory": "contradiction",
}
_NODE_KINDS = {
    "host",
    "service",
    "application",
    "resource",
    "http_operation",
    "api_interface",
    "parameter",
    "form",
    "authentication",
    "technology",
}
_COVERAGE_CODES = {
    "application_signal_limit",
    "browser_api_request_not_completed",
    "browser_capture_partial",
    "historical_discovery_limit",
    "historical_http_without_application_signals",
    "historical_http_without_indicators",
    "http_indicator_limit",
    "http_observation_limit",
    "invalid_url_omitted",
    "navigation_observation_limit",
    "no_packet_count_measurement",
    "no_vulnerability_confirmation",
    "origin_is_inferred_application_boundary",
    "owner_document_is_a_declaration_not_execution",
    "partial_network_run",
    "request_parameter_analysis_incomplete",
    "tcp_connect_only",
    "unfinished_navigation_not_mapped",
}
_STOP_CODES = {
    "cancelled",
    "duration_budget",
    "explicit_plan_completed",
    "incomplete_port_observations",
    "mission_inactive_or_revoked",
    "request_budget",
    "runtime_lost",
    "stop_requested",
}


def _projection_items(run: dict, source: dict) -> list[dict]:
    def item(state: str, kind: str, **details) -> dict:
        return {"state": state, "kind": kind, "source": source, **details}

    kind = run["kind"]
    if kind == "fingerprint":
        items = []
        for entry in run["identifications"]:
            status = entry["status"]
            version = entry["version_status"]
            technology = entry["technology"]
            state = (
                "contradiction"
                if "contradictory" in (status, version)
                else "inference"
                if status in {"probable", "confirmed"}
                else "unknown"
            )
            items.append(
                item(
                    state,
                    "technology_assessment",
                    technology=technology if technology in CATALOG else None,
                    identification_status=status
                    if status in {"confirmed", "probable", "contradictory"}
                    else "unknown",
                    version_status=version
                    if version in {"confirmed", "probable", "contradictory"}
                    else "unknown",
                    version_count=len(entry["versions"]),
                )
            )
        return items
    if kind == "application_map":
        items = []
        for field in ("nodes", "relations"):
            counts = Counter(
                (
                    _MAP_STATES.get(entry["state"], "unknown"),
                    entry["kind"]
                    if field == "nodes" and entry["kind"] in _NODE_KINDS
                    else "graph_element",
                )
                for entry in run[field]
            )
            items.extend(
                item(
                    state,
                    "mapped_elements",
                    element=field,
                    category=category,
                    count=count,
                )
                for (state, category), count in sorted(counts.items())
            )
        return items
    if kind == "network":
        coverage = run["coverage"] or {}
        return [
            item(state, field, count=coverage[field])
            for field, state in (
                ("observed_pairs", "fact"),
                ("unresolved_pairs", "unknown"),
                ("unsubmitted_pairs", "unknown"),
            )
            if type(coverage.get(field)) is int and coverage[field] > 0
        ]
    if kind == "context_run":
        counts = (run["coverage"] or {}).get("states", {})
        return [
            item(
                "fact" if state == "examined" else "unknown",
                "enumeration_coverage",
                outcome=state,
                count=counts[state],
            )
            for state in ("examined", "not_examined", "unknown", "interrupted")
            if type(counts.get(state)) is int and counts[state] > 0
        ]
    return []


def _items(snapshot: dict, snapshot_sha256: str) -> list[dict]:
    items = []
    snapshot_source = {"kind": "mission_snapshot", "sha256": snapshot_sha256}
    with_response = 0
    for row in snapshot["http"]:
        receipt = row["receipt"]
        response = receipt.get("response") if receipt else None
        status = response.get("status") if response else None
        if type(status) is not int or not 100 <= status <= 599:
            continue
        with_response += 1
        items.append(
            {
                "kind": "archived_http_response",
                "state": "fact",
                "status": status,
                "source": {
                    "kind": "http_receipt",
                    "id": receipt["id"],
                    "sha256": row["evidence_sha256"],
                },
            }
        )
    if without_response := len(snapshot["http"]) - with_response:
        items.append(
            {
                "kind": "transactions_without_verified_http_status",
                "state": "unknown",
                "count": without_response,
                "source": snapshot_source,
            }
        )
    if not with_response:
        items.append(
            {
                "kind": "no_archived_http_response",
                "state": "unknown",
                "source": snapshot_source,
            }
        )
    kinds = set()
    contradictions: dict[str, list[str]] = {}
    for row in snapshot["contradictions"]:
        contradictions.setdefault(row["run_id"], []).append(row["observation_id"])
    for run in snapshot["projections"]:
        kinds.add(run["kind"])
        source = {
            "kind": "recon_projection",
            "id": run["id"],
            "sha256": run["archive_sha256"],
        }
        items.extend(_projection_items(run, source))
        for observation_id in contradictions.get(run["id"], []):
            items.append(
                {
                    "kind": "contradictory_observation",
                    "state": "contradiction",
                    "observation_id": observation_id,
                    "source": source,
                }
            )
        if run["limitations"] or run["status"] != "completed":
            codes = sorted(_COVERAGE_CODES.intersection(run["limitations"]))
            items.append(
                {
                    "kind": "projection_coverage_limited",
                    "state": "unknown",
                    "limitation_count": len(run["limitations"]),
                    "limitation_codes": codes,
                    "stop_reason": (
                        run["reason"] if run["reason"] in _STOP_CODES else None
                    ),
                    "run_completed": run["status"] == "completed",
                    "source": source,
                }
            )
    for kind in sorted(
        {"application_map", "context_run", "fingerprint", "network"} - kinds
    ):
        items.append(
            {
                "kind": "no_archived_projection",
                "state": "unknown",
                "projection_kind": kind,
                "source": snapshot_source,
            }
        )
    return items


def mission_review(
    database: str | Path,
    mission_id: UUID,
    *,
    max_context_bytes: int = DEFAULT_CONTEXT_BYTES,
    journal: str | Path | None = None,
    expected_head: str | None = None,
) -> dict:
    """Return the bounded context and optional operator journal metadata."""
    if type(max_context_bytes) is not int or not 4096 <= max_context_bytes <= 131_072:
        raise ValueError("Context limit must be between 4096 and 131072 bytes")
    if expected_head is not None and journal is None:
        raise ValueError("Expected journal path with head checkpoint")
    result = mission_snapshot(database, mission_id)
    report = review_snapshot(result, max_context_bytes=max_context_bytes)
    if journal is not None:
        saved = read_journal(
            journal, mission_id=mission_id, expected_head=expected_head
        )
        report["operator_journal"] = {
            "version": saved["version"],
            "head_sha256": saved["head_sha256"],
            "mission_decisions": len(saved["entries"]),
            "matching_snapshot": sum(
                entry["input"]["snapshot_sha256"] == result["sha256"]
                for entry in saved["entries"]
            ),
        }
    return report


def review_snapshot(
    result: dict, *, max_context_bytes: int = DEFAULT_CONTEXT_BYTES
) -> dict:
    """Build a redacted context from one verified snapshot."""
    if type(max_context_bytes) is not int or not 4096 <= max_context_bytes <= 131_072:
        raise ValueError("Context limit must be between 4096 and 131072 bytes")
    snapshot, sha = result["snapshot"], result["sha256"]
    items = _items(snapshot, sha)
    counts = Counter(item["state"] for item in items)
    registry = capability_registry()
    omitted = {state: counts[state] for state in _CONTEXT_ORDER}
    context = {
        "version": VERSION,
        "snapshot_sha256": sha,
        "snapshot_version": snapshot["version"],
        "recorded_mission_state": snapshot["mission"]["state_at_capture"],
        "capability_registry_version": registry["version"],
        "offline_review_capabilities": [
            capability["id"]
            for capability in registry["capabilities"]
            if capability["mode"] == "offline"
        ],
        "coverage": {
            "exhaustive": False,
            "archived_http_transactions": len(snapshot["http"]),
            "archived_projections": len(snapshot["projections"]),
            "recorded_contradictions": len(snapshot["contradictions"]),
            "omitted_archive_records": sum(
                snapshot["coverage"]["omitted_recon_records_by_kind"].values()
            ),
            "http_archive_present": snapshot["coverage"]["http_archive_present"],
        },
        "omitted_items": omitted,
        "items": [],
    }
    # Account for list separators. Initial omission counts have the most digits,
    # so this bound stays conservative as included items decrement those counts.
    size = len(canonical(context).encode("utf-8"))
    priority = {state: index for index, state in enumerate(_CONTEXT_ORDER)}
    for item in sorted(items, key=lambda value: priority[value["state"]]):
        needed = len(canonical(item).encode("utf-8")) + bool(context["items"])
        if size + needed <= max_context_bytes:
            context["items"].append(item)
            omitted[item["state"]] -= 1
            size += needed

    report = {
        "context": context,
        "size": {
            "canonical_utf8_bytes": len(canonical(context).encode("utf-8")),
            "max_context_bytes": max_context_bytes,
            "available_items": len(items),
            "included_items": len(context["items"]),
        },
        "operator_journal": None,
    }
    return report


def review_with_memory(
    database: str | Path,
    mission_id: UUID,
    memory_root: str | Path,
    *,
    max_context_bytes: int = DEFAULT_CONTEXT_BYTES,
    max_memory_bytes: int = 2048,
    max_memory_items: int = 8,
    memory_query: str = "",
) -> dict:
    """Explicit bounded consultative envelope; free prose never enters model input."""
    from .memory import MemoryEngine

    if type(max_context_bytes) is not int or not 4096 <= max_context_bytes <= 131_072:
        raise ValueError("Context limit must be between 4096 and 131072 bytes")
    if type(max_memory_bytes) is not int or not 512 <= max_memory_bytes <= 16_384:
        raise ValueError("Memory context must be 512 to 16384 bytes")
    base_budget = max_context_bytes - max_memory_bytes - 64
    if base_budget < 4096:
        raise ValueError("Combined context must reserve at least 4096 base bytes")
    snapshot = mission_snapshot(database, mission_id)
    report = review_snapshot(snapshot, max_context_bytes=base_budget)
    memory = MemoryEngine(memory_root, mission_id).working_context(
        snapshot,
        query=memory_query,
        max_bytes=max_memory_bytes,
        max_items=max_memory_items,
    )
    report["memory_context"] = memory
    measured = len(
        canonical({"context": report["context"], "memory_context": memory}).encode()
    )
    if measured > max_context_bytes:
        raise ValueError("Combined context exceeds byte limit")
    report["size"].update(
        additional_memory_utf8_bytes=len(canonical(memory).encode()),
        combined_context_utf8_bytes=measured,
        max_combined_context_bytes=max_context_bytes,
        max_memory_bytes=max_memory_bytes,
        max_memory_items=max_memory_items,
    )
    return report
