"""Coverage of recorded evidence for the client report, in catalogue order."""

from collections import Counter
from typing import TypedDict
from uuid import UUID

from .contracts import _digest

# Family identifiers follow docs/product/WEB_CAPABILITIES.md. Labels are kept
# local and static so that target content cannot become report markup.
FAMILIES = (
    "Surface externe",
    "SPA et API observées dans le navigateur",
    "TLS, configuration et exposition",
    "Redirections et navigation",
    "Identités et authentification",
    "Sessions et jetons",
    "Contrôle d’accès",
    "Injections dans les langages de requête",
    "XSS et injection HTML",
    "Injections côté serveur",
    "Chemins et lecture de fichiers",
    "Téléversement et traitement de fichiers",
    "Interactions serveur et parseurs XML",
    "CSRF, CORS et confiance interorigine",
    "Contrôles de sécurité des API REST",
    "Logique métier",
    "Erreurs, données sensibles et cache",
    "Concurrence et idempotence",
    "GraphQL et WebSocket",
    "SSO et chaînes avancées",
)

STATUS_LABELS = {
    "observed": "Observé",
    "not_observed": "Non observé",
    "not_tested": "Non testé",
    "inconclusive": "Inconclusif",
    "partial": "Partiel",
    "targeted_check_completed": "Contrôle ciblé effectué",
}


class CoverageResult(TypedDict):
    status: str
    detail: str
    counts: dict[str, int]


class CoverageRow(CoverageResult):
    family_id: str
    family: str


class CoverageExport(TypedDict):
    schema_version: int
    mission_id: str
    run_id: str
    configuration_sha256: str
    families: list[CoverageRow]


def _redirect_coverage(checks: list[dict]) -> CoverageResult:
    # A prior confirmation and its recheck must remain visible as distinct
    # outcomes. These counts are records, rather than unique findings.
    verdicts = Counter(check["verdict"] for check in checks)
    confirmed = verdicts["confirmed"]
    negative = verdicts["not_confirmed"]
    inconclusive = verdicts["inconclusive"]
    pending = len(checks) - confirmed - negative - inconclusive
    if confirmed or negative:
        status = "partial" if inconclusive or pending else "targeted_check_completed"
    elif inconclusive:
        status = "inconclusive"
    else:
        status = "not_tested"
    detail = (
        f"Redirection externe uniquement. Contrôles et recontrôles : {confirmed} "
        f"confirmé(s), {negative} non reproduit(s), {inconclusive} inconclusif(s), "
        f"{pending} sans résultat."
        if checks
        else "Aucun contrôle de sécurité enregistré dans cette famille."
    )
    return CoverageResult(
        status=status,
        detail=detail,
        counts=dict(
            confirmed=confirmed,
            not_reproduced=negative,
            inconclusive=inconclusive,
            no_result=pending,
        ),
    )


def coverage_rows(report: dict) -> list[CoverageRow]:
    pages = sum(
        entry["kind"] == "page" and entry.get("request_state") == "completed"
        for entry in report["surface"]
    )
    browser = report["browser"]
    # Derive counts from the existing projections without copying URL content.
    apis = len(browser["observed_apis"])
    links = len(browser["observed_links"])
    statuses: dict[int, CoverageResult] = {
        1: CoverageResult(
            status="observed" if pages else "not_observed",
            detail=f"{pages} échange(s) de découverte terminé(s) sur des pages."
            if pages
            else "Aucun échange de découverte terminé sur une page.",
            counts=dict(completed_page_exchanges=pages),
        ),
        2: CoverageResult(
            status="observed" if apis or links else "not_observed",
            detail=f"{apis} appel(s) API et {links} lien(s) DOM relevé(s)."
            if apis or links
            else "Aucun appel API ni lien DOM relevé.",
            counts=dict(api_observations=apis, dom_links=links),
        ),
        4: _redirect_coverage(report["redirect_checks"]),
    }
    unsupported = CoverageResult(
        status="not_tested", detail="Aucun contrôle de sécurité enregistré.", counts={}
    )
    return [
        CoverageRow(
            family_id=f"WEB-{number:02d}",
            family=family,
            **statuses.get(number, unsupported),
        )
        for number, family in enumerate(FAMILIES, start=1)
    ]


def coverage_export(report: dict) -> CoverageExport:
    fingerprint = report["configuration_sha256"]
    _digest(fingerprint)
    return CoverageExport(
        schema_version=1,
        mission_id=str(UUID(report["mission_id"])),
        run_id=str(UUID(report["run_id"])),
        configuration_sha256=fingerprint,
        families=coverage_rows(report),
    )
