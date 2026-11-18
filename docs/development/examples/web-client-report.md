# Rapport web Argos

## Synthèse

- Mission `00000000-0000-0000-0000-000000000001`
- Exécution `00000000-0000-0000-0000-000000000002`
- État `completed` (`frontier_exhausted`)
- Constats confirmés au moins une fois : 1

Ce rapport restitue la découverte anonyme et le contrôle de redirection disponible. Les parcours authentifiés et les autres familles de sécurité restent non testés par cette exécution. La gravité et l’impact métier des constats restent à qualifier.

## Périmètre et couverture

- Configuration de mission, SHA-256 `eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`
- Entrées de cartographie : 3 (pages et témoins HTTP).
- Échanges HTTP de découverte terminés : 3.
- États des entrées : `visited`: 3.
- Motifs relevés : `html`: 1, `not_found`: 1, `redirect`: 1.
- Limites rencontrées : Aucun.
- Rendus navigateur : 0. États : Aucun.
- Motifs de blocage des ressources navigateur : Aucun.
- Liens DOM observés : 0.
- Appels API observés : 0. L’observation ne valide aucun contrôle de sécurité de ces API.
- Contrôle de redirection : `executed`.
- Motifs des contrôles inconclusifs : Aucun.

### Couverture par famille

Les identifiants renvoient au catalogue Argos. Chaque ligne décrit les éléments enregistrés pour cette exécution.

| ID | Famille | État | Éléments enregistrés |
| --- | --- | --- | --- |
| WEB-01 | Surface externe | Observé | 2 échange(s) de découverte terminé(s) sur des pages. |
| WEB-02 | SPA et API observées dans le navigateur | Non observé | Aucun appel API ni lien DOM relevé. |
| WEB-03 | TLS, configuration et exposition | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-04 | Redirections et navigation | Contrôle ciblé effectué | Redirection externe uniquement. Contrôles et recontrôles : 1 confirmé(s), 1 non reproduit(s), 0 inconclusif(s), 0 sans résultat. |
| WEB-05 | Identités et authentification | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-06 | Sessions et jetons | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-07 | Contrôle d’accès | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-08 | Injections dans les langages de requête | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-09 | XSS et injection HTML | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-10 | Injections côté serveur | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-11 | Chemins et lecture de fichiers | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-12 | Téléversement et traitement de fichiers | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-13 | Interactions serveur et parseurs XML | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-14 | CSRF, CORS et confiance interorigine | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-15 | Contrôles de sécurité des API REST | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-16 | Logique métier | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-17 | Erreurs, données sensibles et cache | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-18 | Concurrence et idempotence | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-19 | GraphQL et WebSocket | Non testé | Aucun contrôle de sécurité enregistré. |
| WEB-20 | SSO et chaînes avancées | Non testé | Aucun contrôle de sécurité enregistré. |

## Constats et preuves

### Redirection externe · `00000000-0000-0000-0000-000000000004`

- Route `00000000-0000-0000-0000-000000000003` · paramètre à l’index 0 (base zéro).
- Statut : Non reproduit au dernier recontrôle.
- Effet observé : l’application a renvoyé une redirection vers une destination externe contrôlée par la valeur du paramètre.
- Correction proposée : privilégier les chemins internes ou limiter les destinations externes à une liste explicite.
- Première confirmation `00000000-0000-0000-0000-000000000004` · 2026-11-17T10:00:00+00:00 · Comportement confirmé (`two_markers_matched`).
  - Reçu `00000000-0000-0000-0000-000000000028` · SHA-256 `0000000000000000000000000000000000000000000000000000000000000028`.
  - Reçu `00000000-0000-0000-0000-000000000029` · SHA-256 `0000000000000000000000000000000000000000000000000000000000000029`.
  - Reçu `00000000-0000-0000-0000-00000000002a` · SHA-256 `000000000000000000000000000000000000000000000000000000000000002a`.

## Recontrôle

- Contrôle initial `00000000-0000-0000-0000-000000000004` · 2026-11-17T10:00:00+00:00 · Comportement confirmé (`two_markers_matched`).
  - Reçu `00000000-0000-0000-0000-000000000028` · SHA-256 `0000000000000000000000000000000000000000000000000000000000000028`.
  - Reçu `00000000-0000-0000-0000-000000000029` · SHA-256 `0000000000000000000000000000000000000000000000000000000000000029`.
  - Reçu `00000000-0000-0000-0000-00000000002a` · SHA-256 `000000000000000000000000000000000000000000000000000000000000002a`.
- Recontrôle `00000000-0000-0000-0000-000000000005` · 2026-11-18T10:00:00+00:00 · Comportement non reproduit (`external_redirect_not_reproduced`).
  - Reçu `00000000-0000-0000-0000-000000000032` · SHA-256 `0000000000000000000000000000000000000000000000000000000000000032`.
  - Reçu `00000000-0000-0000-0000-000000000033` · SHA-256 `0000000000000000000000000000000000000000000000000000000000000033`.
  - Reçu `00000000-0000-0000-0000-000000000034` · SHA-256 `0000000000000000000000000000000000000000000000000000000000000034`.
