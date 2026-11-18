"""Client Markdown generated from the existing read-only web projection."""

from collections import Counter
from datetime import UTC, datetime
from re import fullmatch
from uuid import UUID

from .contracts import WebErrorCode
from .frontier import BLOCKED, GAPS
from .navigation_evidence import REASONS as RESOURCE_REASONS
from .report_coverage import STATUS_LABELS, coverage_rows

RUN_STATES = {"running", "completed", "partial", "stopped", "interrupted"}
ROUTE_STATES = {"queued", "visited", "excluded", "blocked", "interrupted"}
NAVIGATION_STATES = RUN_STATES | {"pending", "reserved", "failed", "cancelled"}
REASONS = (
    BLOCKED
    | GAPS
    | RESOURCE_REASONS
    | {code.value for code in WebErrorCode}
    | {
        "running",
        "resumed",
        "coverage_partial",
        "frontier_exhausted",
        "stop_requested",
        "runtime_interrupted",
        "invalid_url",
        "pending",
        "html",
        "redirect",
        "not_found",
        "profile_changed",
        "login_redirect",
        "limited",
        "awaiting_exchanges",
        "two_markers_matched",
        "external_redirect_not_reproduced",
        "exchange_incomplete",
        "observation_missing",
        "access_or_response_blocked",
        "baseline_rejected",
    }
)
VERDICTS = {
    "not_tested": "Non effectué",
    "confirmed": "Comportement confirmé",
    "not_confirmed": "Comportement non reproduit",
    "inconclusive": "Résultat inconclusif",
}
FINDING_STATES = {
    "confirmed": "Confirmé",
    "not_reproduced": "Non reproduit au dernier recontrôle",
    "retest_inconclusive": "Dernier recontrôle inconclusif",
}


def _label(value: str, allowed: set[str] | frozenset[str]) -> str:
    # Never interpolate external text, even inside Markdown code spans.
    return f"`{value}`" if value in allowed else "Non classé"


def _sha256(value: str) -> str:
    if not fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Invalid evidence fingerprint")
    return value


def _count(value: int) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("Invalid report count")
    return value


def _counts(values: dict, allowed: set[str] | frozenset[str]) -> str:
    counts: Counter[str] = Counter()
    for value, count in values.items():
        counts[_label(value, allowed)] += _count(count)
    return (
        ", ".join(f"{label}: {count}" for label, count in sorted(counts.items()))
        or "Aucun"
    )


def _check(lines: list[str], check: dict, title: str) -> None:
    recorded = datetime.fromisoformat(check["recorded_at"])
    if recorded.tzinfo is None:
        raise ValueError("Missing evidence timestamp offset")
    date = recorded.astimezone(UTC).isoformat()
    verdict = VERDICTS.get(check["verdict"], "Non classé")
    reason = _label(check["reason"], REASONS)
    lines.append(f"- {title} `{UUID(check['id'])}` · {date} · {verdict} ({reason}).")
    for step in check["steps"]:
        if fingerprint := step["receipt_sha256"]:
            lines.append(
                f"  - Reçu `{UUID(step['request_id'])}` · "
                f"SHA-256 `{_sha256(fingerprint)}`."
            )


def render_markdown(report: dict) -> str:
    browser = report["browser"]
    findings = report["findings"]
    checks = report["redirect_checks"]
    checks_by_id = {check["id"]: check for check in checks}
    completed_http = sum(
        route.get("request_state") == "completed" for route in report["surface"]
    )
    browser_blocks = Counter(
        resource["reason"]
        for navigation in browser["navigation_details"]
        for resource in navigation["resources"]
        if resource["state"] == "blocked"
    )
    inconclusive = Counter(
        check["reason"] for check in checks if check["verdict"] == "inconclusive"
    )
    redirect_state = _label(
        report["redirect_verification"]["state"], {"not_tested", "partial", "executed"}
    )
    lines = [
        "# Rapport web Argos",
        "",
        "## Synthèse",
        "",
        f"- Mission `{UUID(report['mission_id'])}`",
        f"- Exécution `{UUID(report['run_id'])}`",
        f"- État {_label(report['status'], RUN_STATES)} "
        f"({_label(report['reason'], REASONS)})",
        f"- Constats confirmés au moins une fois : {len(findings)}",
        "",
        "Ce rapport restitue la découverte anonyme et le contrôle de redirection "
        "disponible. Les parcours authentifiés et les autres familles de sécurité "
        "restent non testés par cette exécution. La gravité et l’impact métier "
        "des constats restent à qualifier.",
        "",
        "## Périmètre et couverture",
        "",
        "- Configuration de mission, SHA-256 "
        f"`{_sha256(report['configuration_sha256'])}`",
        f"- Entrées de cartographie : {_count(report['routes'])} "
        "(pages et témoins HTTP).",
        f"- Échanges HTTP de découverte terminés : {completed_http}.",
        f"- États des entrées : {_counts(report['states'], ROUTE_STATES)}.",
        f"- Motifs relevés : {_counts(report['reasons'], REASONS)}.",
        f"- Limites rencontrées : {_counts(report['limits'], REASONS)}.",
        f"- Rendus navigateur : {_count(browser['navigations'])}. "
        f"États : {_counts(browser['states'], NAVIGATION_STATES)}.",
        "- Motifs de blocage des ressources navigateur : "
        f"{_counts(browser_blocks, REASONS)}.",
        f"- Liens DOM observés : {_count(browser['dom_links'])}.",
        f"- Appels API observés : {_count(browser['api_observations'])}. "
        "L’observation ne valide aucun contrôle de sécurité de ces API.",
        f"- Contrôle de redirection : {redirect_state}.",
        f"- Motifs des contrôles inconclusifs : {_counts(inconclusive, REASONS)}.",
        "",
        "### Couverture par famille",
        "",
        "Les identifiants renvoient au catalogue Argos. Chaque ligne décrit les "
        "éléments enregistrés pour cette exécution.",
        "",
        "| ID | Famille | État | Éléments enregistrés |",
        "| --- | --- | --- | --- |",
        *(
            f"| {row['family_id']} | {row['family']} | "
            f"{STATUS_LABELS[row['status']]} | {row['detail']} |"
            for row in coverage_rows(report)
        ),
        "",
        "## Constats et preuves",
        "",
    ]
    if not findings:
        lines.extend(["Aucun constat confirmé dans les données disponibles.", ""])
    for finding in findings:
        initial = checks_by_id[finding["id"]]
        later = [check for check in checks if check["parent_id"] == initial["id"]]
        confirmed = next(
            check for check in [initial, *later] if check["verdict"] == "confirmed"
        )
        lines.extend(
            [
                f"### Redirection externe · `{UUID(finding['id'])}`",
                "",
                f"- Route `{UUID(finding['route_id'])}` · paramètre à l’index "
                f"{_count(finding['parameter_index'])} (base zéro).",
                f"- Statut : {FINDING_STATES.get(finding['status'], 'Non classé')}.",
                "- Effet observé : l’application a renvoyé une redirection vers "
                "une destination externe contrôlée par la valeur du paramètre.",
                "- Correction proposée : privilégier les chemins internes ou "
                "limiter les destinations externes à une liste explicite.",
            ]
        )
        _check(lines, confirmed, "Première confirmation")
        lines.append("")

    lines.extend(["## Recontrôle", ""])
    if not any(check["parent_id"] is not None for check in checks):
        lines.extend(["Aucun recontrôle enregistré.", ""])
    for check in checks:
        if check["parent_id"] is not None:
            _check(lines, checks_by_id[check["parent_id"]], "Contrôle initial")
            _check(lines, check, "Recontrôle")
            lines.append("")
    return "\n".join(lines)
