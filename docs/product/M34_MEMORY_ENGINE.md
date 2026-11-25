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

Depuis M3.5-C.1, consulter la [configuration des données locales](M351_DATA_ARCHITECTURE.md)
pour les nouveaux chemins et la migration.

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

## Qualification hors ligne

Le banc `benchmarks/llm/qualify_memory.py` réutilise les trois revues M3.3
archivées, sans appel au modèle et sans réseau. Il capture chaque revue dans
une nouvelle mémoire, vérifie l'idempotence, interroge les réponses HTTP 200,
compare exactement leurs identifiants aux reçus de l'archive, vérifie l'absence
d'un marqueur indépendant et tente de récupérer des identifiants d'une autre
mission. Il hache bases sources et journal avant/après. Trente récupérations
par mission fournissent les durées brutes ; la médiane et le percentile 95
(rang 29/30) sont archivés. Le contexte total est plafonné à 8 192 octets,
dont au plus 2 048 pour la mémoire et 8 éléments.

```bash
PYTHONPATH=. .venv/bin/python benchmarks/llm/qualify_memory.py \
  --journal REVUES.sqlite --reviews SUMMARY_M33.json \
  --archives-root .argos/qualifications/m271 \
  --output "$HOME/.local/share/argos/qualification/m34"
```

Mesures du 25 novembre 2026, sur la version avec chemins de provenance :

| Archive | Enregistrements | SQLite Kio | Capture ms | Recherche médiane / p95 ms | Complément mémoire octets | Total contexte octets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| crAPI | 79 | 92 | 913 | 5,92 / 8,49 | 1 856 | 7 810 |
| DVWA | 82 | 96 | 737 | 5,65 / 8,98 | 1 699 | 7 714 |
| Juice Shop | 96 | 108 | 2 548 | 7,94 / 11,25 | 1 823 | 7 785 |

Chaque complément contient 3 éléments sous ces plafonds. La capture et la
construction complète du contexte revérifient les sources ; les coûts complets
de contexte sont respectivement 922, 572 et 2 200 ms. Ces mesures indicatives
ont eu lieu pendant les tests réguliers ; elles ne sont pas un benchmark de
latence isolé ni une mesure de charge maximale. Le coût SQLite exclut les
archives et journaux préexistants, conservés séparément sans modification.

La récupération exacte des reçus HTTP 200 atteint précision/rappel 100 % sur
38, 5 et 48 reçus respectivement. Il s'agit d'une requête factuelle précise,
pas d'une note de pertinence sémantique universelle. Le test indépendant des
fixtures HTTP 200/404 contrôle également la sélection attendue et les requêtes
sans correspondance. Aucune référence d'une mission étrangère n'a été rendue.

Les fixtures qualifient aussi origines humaines/LLM séparées, erreur d'inférence,
contradictions préservées, snapshot devenu obsolète, suppression des doublons,
altération de mémoire et de preuve, checkpoint externe, UID changé simulé,
copie du fichier entre missions, permissions trop larges, symlinks et hardlinks.
La vérification de l'identité utilise les propriétés Unix, sans prétendre à
un essai de deux sessions Web authentifiées. Les textes d'injection conservés
comme annotations ne traversent pas le complément de contexte.

Les résultats détaillés et configurations sont privés :
`~/.local/share/argos/qualification/m34/7ae823a6-3aeb-46e8-95d8-6480b09a83e8/`.
Ils contiennent `configuration.json`, `results.json` (dont les 90 durées brutes)
et `memory/uid-UID/UUID.sqlite`. La première mesure exploratoire, avant ajout
des chemins privés de provenance, reste conservée sous
`942c1f3f-4454-455d-9fd0-00cd359042d9` ; les baselines M3.2.1/M3.3 et M2.7.1
sont préservées. ROOT doit être conservé sous un répertoire hôte de confiance,
sauvegardé par l'opérateur. Les traces et mémoires ne doivent pas être publiées.

## Validation de livraison

Les 20 tests ciblés de mémoire et CLI passent sous Python 3.12 et 3.14.
La suite régulière finale compte **1 266 réussites, 121 ignorés** sous chaque
interpréteur. Les essais hôte optionnels de reconnaissance, isolation et
navigateur restent désactivés ; aucun essai réseau ni inférence supplémentaire
n'est revendiqué. Ruff, formatage, Pyright, liens documentaires et
`git diff --check` passent.

```bash
.venv/bin/python -m pytest -q tests/test_review_memory.py tests/test_review_memory_cli.py
/tmp/argos-stabilization-py312/bin/python -m pytest -q tests/test_review_memory.py tests/test_review_memory_cli.py
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
# Sans ARGOS_TEST_{NETWORK,ISOLATION,BROWSER,TOOL_REGISTRY}, pour chaque interpréteur
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -q -o faulthandler_timeout=30
git diff --check
```

Les journaux complets sont conservés sous le répertoire privé M3.4,
`tests-py312.log` et `tests-py314.log`. Le stockage SQLite de cette tranche
n'ajoute aucune dépendance à `pyproject.toml`. La branche
`feat/m34-memory-engine` reste locale pour validation, sans merge ni push.
M3.5 n'a pas été commencé.


## Consolidation et publication

La demande opérateur de consolidation lève la restriction initiale de merge/push.
Avant publication, les empreintes des sources et des preuves privées correspondent
au manifeste de qualification conservé ; les journaux complets confirment
1 266 réussites et 121 ignorés sur Python 3.12 et 3.14. Les 20 tests ciblés sont
réexécutés sur chaque interpréteur ; Ruff, formatage et Pyright passent.
Intégration de la branche dans main par fast-forward, puis push de main et
vérification de la CI du SHA publié. Les limitations de qualité LLM et de
cloisonnement local restent applicables. Aucune branche n'est supprimée lors
de cette consolidation ; M3.5 n'est pas commencé.
