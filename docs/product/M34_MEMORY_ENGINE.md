# M3.4 — Mémoire consultative des missions

## Audit préalable

`AGENTIC_CORE.md` décrit une architecture cible : mémoire, contexte et
apprentissage y sont distincts. Les tables d'expérience, embeddings et méthodes
réutilisables ne sont pas livrées et ne sont pas des prérequis de M3.4.
Le code existant fournit :

- `mission_snapshot` : copie cohérente, preuves HTTP et projections vérifiées ;
- `_items` / `review_snapshot` : observations structurées expurgées et plafonds ;
- `read_workflow` : captures, analyses, erreurs, annotations et états chaînés ;
- `read_journal` : décisions humaines explicites et références de preuve ;
- `canonical` / `digest` : format stable et empreintes SHA-256.

Il manque un espace de travail courant, un index consultable de revues antérieures,
une politique de fraîcheur/suppression et un contrat borné de récupération.
Aucun principal applicatif authentifié n'existe dans ces composants : les
`owner_id` du runtime identifient des processus, pas des utilisateurs. M3.4
utilisera donc l'UID Unix effectif, les permissions hôte et un fichier par mission.
Aucun argument CLI ne permettra de choisir l'identité d'un autre utilisateur.
Ce choix ne prétend pas fournir une authentification multi-utilisateur Web.

La mémoire conserve les origines séparément : archive vérifiée à l'import
(avec état fact/inference/contradiction/unknown), annotation humaine, décision
validée, résultat LLM, erreur et limitations. Elle ne transforme pas une sortie
LLM ni une conclusion humaine en observation vérifiée. Les annotations libres
et les sorties LLM ne sont pas injectées automatiquement dans le contexte.

La recherche initiale sera lexicale et déterministe, sans dépendance nouvelle,
embeddings, apprentissage ni Knowledge Engine M3.5.
