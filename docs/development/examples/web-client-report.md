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
