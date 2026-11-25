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

## Contrats et utilisation

`MemoryEngine(root, mission_id)` expose `capture`, `search`, `get`, `focus`,
`forget`, `info` et `working_context`. Le contrat de récupération `MemoryReader`
est une frontière typée pour les futurs consommateurs de connaissances ;
aucun Knowledge Engine ni mécanisme d'apprentissage n'est implémenté.

Le stockage est `ROOT/uid-UID/UUID_MISSION.sqlite`. ROOT et son sous-répertoire
sont privés (700), le fichier est privé (600), et propriétaire Unix, identité
stockée, UUID et empreintes sont vérifiés avant récupération. Les symlinks et
les fichiers ayant plusieurs liens sont refusés. Un UID effectif différent
ne peut pas être choisi par argument. Les programmes sous le même compte Unix
partagent cependant le même domaine de confiance ; les administrateurs hôte,
comptes partagés et clients Web multi-tenant ne sont pas isolés par ce contrat.

Une capture est dérivée d'une revue M3.3 et de son archive vérifiée au même
snapshot. Chaque enregistrement porte origine, mission, revue, empreinte du
snapshot et de l'événement source, date de l'événement et références de preuve
pour les observations. `date_basis=review_event` évite de prétendre connaître
une date d'observation absente. Les imports répétés sont idempotents.
Les autres origines gardent leurs liens à l'événement de revue et ne deviennent
jamais des observations vérifiées. Les erreurs et limitations restent visibles.

La recherche porte sur au plus 8 termes littéraux distincts et 256 octets,
avec conjonction AND, filtre d'origine facultatif et limite de 1 à 100 résultats.
Elle n'utilise ni SQL libre, ni expressions exécutables, ni similarité vectorielle.
Les états contradictoires/inconnus passent avant les faits ordinaires, puis
la date et l'identifiant départagent les résultats. Les doublons exacts d'une
observation avec la même preuve sont groupés par snapshot, sans fusionner les
états ni prétendre résoudre les contradictions. `get` restitue une occurrence.

La première revue importée devient le contexte de travail. Les imports suivants
ne changent pas la focalisation ; `focus` la change explicitement. Les données
d'un autre snapshot portent `stale=true` et sont exclues par défaut ;
`--include-stale` permet la consultation historique. Cette fraîcheur est relative
à la revue choisie, pas à l'état actuel de la cible ; il n'y a ni nouvelle
observation réseau ni expiration automatique arbitraire.

La chaîne versionnée conserve captures, focalisation et tombstones.
`info --expected-head` vérifie un checkpoint gardé séparément. Un propriétaire
malveillant capable de réécrire toute la base et ses empreintes n'est pas
empêché par SHA-256. Les suppressions sont logiques : les données demeurent
dans l'historique privé et ses sauvegardes, sans promesse d'effacement physique.

```bash
# ROOT absent ou privé ; défaut configurable avec ARGOS_MEMORY_HOME
.venv/bin/python -m argos review memory-capture --memory-root ROOT \
  --mission-id MISSION_UUID --db ARCHIVE --journal JOURNAL --review-id REVIEW_UUID
.venv/bin/python -m argos review memory-info --memory-root ROOT --mission-id MISSION_UUID
.venv/bin/python -m argos review memory-search --memory-root ROOT \
  --mission-id MISSION_UUID --query 'archived_http_response status 200' \
  --origin verified_archive --limit 20
.venv/bin/python -m argos review memory-focus --memory-root ROOT \
  --mission-id MISSION_UUID --review-id REVIEW_UUID
.venv/bin/python -m argos review memory-get --memory-root ROOT \
  --mission-id MISSION_UUID --entry-id SHA256
# Fichier privé 600 : {"reason":"motif explicite"}
.venv/bin/python -m argos review memory-delete --memory-root ROOT \
  --mission-id MISSION_UUID --entry-id SHA256 --input SUPPRESSION.json
```

## Contexte contrôlé

```bash
.venv/bin/python -m argos review summary --db ARCHIVE --mission-id MISSION_UUID \
  --memory-root ROOT --max-context-bytes 8192 --max-memory-bytes 2048 \
  --max-memory-items 8 --memory-query 'unknown'
```

`review_with_memory` produit une enveloppe consultative séparant `context` et
`memory_context`. Le plafond total inclut les deux objets JSON canoniques ;
la taille mémoire, le nombre d'éléments et les omissions sont mesurés. La
réservation mémoire réduit le budget de la vue de base ; un budget trop petit
est refusé. Par défaut : total 32 Kio, mémoire 2 Kio et 8 éléments ; limites
mémoire 512–16 384 octets, 1–32 éléments, total au plus 128 Kio avec au moins
4 Kio réservés à la base.

Seules les observations structurées `verified_archive` correspondant exactement
au snapshot actuel entrent dans ce complément. Les preuves sont recontrôlées
contre les observations de ce snapshot. Un changement de snapshot produit un
complément vide avec `working_snapshot_differs`. Les textes libres humains,
erreurs et sorties LLM restent consultables mais sont exclus du complément.
L'analyste M3.2 conserve son entrée expurgée historique : il ne consomme pas
implicitement cette enveloppe supplémentaire. Une future intégration devra
rester explicite et bornée. Ni mémoire ni annotation n'autorise une exécution.

Les chemins privés `source_archive` et `source_journal` permettent de retrouver
les sources d'une occurrence. Ils ne sont pas transmis dans le complément de
contexte. Une suppression s'applique au contenu exact et à sa preuve, y compris
ses doublons dans d'autres revues ; leur réimport ne les rend pas consultables.
Elle ne supprime ni l'archive d'origine ni les événements d'audit.
Un import historique exige une archive correspondant au snapshot de la revue ;
les captures déjà importées restent consultables après évolution de l'archive.

Capacité de cette version : 20 000 enregistrements, 10 000 événements et 64 Kio
par enregistrement. La recherche et la vérification rejouent l'historique en
mémoire ; ces plafonds ne constituent pas une qualification de charge maximale.
La recherche est littérale, sans compréhension de synonymes ni classement
sémantique. La mémoire ne corrige pas la qualité des analyses LLM mesurée en
M3.2.1 ; une référence valide ne suffit toujours pas à démontrer leur pertinence.
