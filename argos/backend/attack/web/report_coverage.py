"""Coverage of recorded evidence for the client report, in catalogue order."""

from collections import Counter

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


def _redirect_coverage(checks: list[dict]) -> tuple[str, str]:
    # A prior confirmation and its recheck must remain visible as distinct
    # outcomes. These counts are records, rather than unique findings.
    verdicts = Counter(check["verdict"] for check in checks)
    confirmed = verdicts["confirmed"]
    negative = verdicts["not_confirmed"]
    inconclusive = verdicts["inconclusive"]
    pending = len(checks) - confirmed - negative - inconclusive
    if not checks:
        return "Non testé", "Aucun contrôle de sécurité enregistré dans cette famille."
    if confirmed or negative:
        status = "Partiel" if inconclusive or pending else "Contrôle ciblé effectué"
    elif inconclusive:
        status = "Inconclusif"
    else:
        status = "Non testé"
    return status, (
        f"Redirection externe uniquement. Contrôles et recontrôles : {confirmed} "
        f"confirmé(s), {negative} non reproduit(s), {inconclusive} inconclusif(s), "
        f"{pending} sans résultat."
    )


def coverage_rows(report: dict) -> list[tuple[str, str, str, str]]:
    pages = sum(
        entry["kind"] == "page" and entry.get("request_state") == "completed"
        for entry in report["surface"]
    )
    browser = report["browser"]
    # Derive counts from the existing projections without copying URL content.
    apis = len(browser["observed_apis"])
    links = len(browser["observed_links"])
    statuses = {
        1: (
            ("Observé", f"{pages} échange(s) de découverte terminé(s) sur des pages.")
            if pages
            else ("Non observé", "Aucun échange de découverte terminé sur une page.")
        ),
        2: (
            ("Observé", f"{apis} appel(s) API et {links} lien(s) DOM relevé(s).")
            if apis or links
            else ("Non observé", "Aucun appel API ni lien DOM relevé.")
        ),
        4: _redirect_coverage(report["redirect_checks"]),
    }
    return [
        (
            f"WEB-{number:02d}",
            family,
            *statuses.get(
                number, ("Non testé", "Aucun contrôle de sécurité enregistré.")
            ),
        )
        for number, family in enumerate(FAMILIES, start=1)
    ]
