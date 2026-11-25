# M3.3 — Supervised Review Workflow

Le workflow coordonne la revue consultative de missions archivées. Il réutilise
le snapshot vérifié M3.1, son Evidence Engine, le contexte expurgé, l'analyste
M3.2 et le Decision Journal. Il ne sélectionne pas d'action offensive et
n'importe aucun mécanisme d'exécution ni d'autorisation de mission.

## Contrat et persistance

`workflow.py` expose `create_workflow`, `read_workflow`, `analyze_workflow`,
`annotate_workflow`, `interrupt_workflow` et `accept_workflow`. Chaque revue
possède un UUID ; son historique est versionné `supervised-review-v1`.
Les événements sont conservés dans le SQLite privé du journal opérateur, séparé
de la base de mission. L'[ADR 0003](../architecture/adr/0003-supervised-review-journal.md)
explique les transactions, empreintes et limites de reprise.

La création fige **un seul** snapshot vérifié, son contexte compact de 8 Kio,
les preuves et **tous** les éléments `contradiction` / `unknown` exposés par le
snapshot, avant la réduction du contexte ou la déduplication du modèle.
Ce volet critique persiste sur succès, erreur et interruption. Les limites
propres au snapshot (archives plafonnées, projections absentes) restent
visibles ; « complet » signifie ici complet dans cette vue, pas dans le monde
réel. Les autres faits et inférences restent consultables via le contexte
et la synthèse, avec leurs sources.

Le cycle est `created → analyzing → ready | failed | interrupted`, puis
`ready → accepted`. Une reprise explicite peut repartir de `failed`,
`interrupted` ou `ready` vers `analyzing` ; une revue acceptée reste terminale.
Une nouvelle revue est requise si le snapshot actuel diffère. Les preuves
sont revérifiées avant chaque inférence et acceptation. Le refus d'une archive
altérée ne lance pas de modèle et laisse l'état précédent intact.

Chaque tentative conserve le prompt exact expurgé, le schéma, leur empreinte,
le fournisseur, le nom configurable du modèle, port, timeout, options fixes
M3.2, réponse structurée du fournisseur, usage tokens, latences, résultat et
erreur bornée. La réponse stockée est la `LLMCompletion` du contrat fournisseur,
pas le corps HTTP brut Ollama ; ce dernier est conservé par le banc M3.2.1.
La configuration lie un nom/tag de modèle : elle ne certifie pas à elle seule
que des poids sous ce tag n'ont jamais changé. Les tables ne constituent pas
une signature cryptographique contre leur propriétaire.

Un état `analyzing` après arrêt brutal n'est jamais relancé implicitement.
Après vérification que le processus est mort, l'opérateur le marque interrompu
et relance une tentative. Cette opération ne tue pas un serveur Ollama vivant.
Les réponses tardives d'une tentative remplacée sont refusées par comparaison
de l'empreinte précédente. Les annotations attendent la fin d'une inférence.
Les erreurs inattendues du fournisseur sont tracées par un code sûr et le
type d'erreur, sans contenu de l'exception ; une reprise reste possible.

La validation exige une décision explicitement fournie par l'humain, avec
motivation, contexte et références vérifiées selon le contrat M3.1. Elle est
archivée par le Decision Journal, puis liée à l'analyse et à la revue.
`execution_authorized` reste toujours `false`. Ni les annotations ni les
conclusions du modèle ne deviennent des instructions exécutables.

## Utilisation CLI

```bash
# Journal créé en mode 600 ; archive source privée existante, jamais modifiée
.venv/bin/python -m argos review workflow-start \
  --db ARCHIVE.sqlite --mission-id UUID --journal JOURNAL.sqlite
# Conserver le review_id renvoyé
.venv/bin/python -m argos review workflow-show \
  --journal JOURNAL.sqlite --review-id REVIEW_UUID
# Démarrer séparément le serveur local, puis analyser explicitement
scripts/llm/ollama-local serve
.venv/bin/python -m argos review workflow-analyze \
  --db ARCHIVE.sqlite --journal JOURNAL.sqlite --review-id REVIEW_UUID --model qwen3:4b
# Note JSON privée : {"operator":"nom","note":"constat de revue"}
.venv/bin/python -m argos review workflow-annotate \
  --journal JOURNAL.sqlite --review-id REVIEW_UUID --input NOTE.json
# Après mort vérifiée du processus, même contrat JSON pour expliciter la reprise
.venv/bin/python -m argos review workflow-interrupt \
  --journal JOURNAL.sqlite --review-id REVIEW_UUID --input INTERRUPTION.json
# Puis workflow-analyze relance explicitement une nouvelle tentative
# Validation : contrat JSON du journal M3.1, jamais rédigé par le modèle
.venv/bin/python -m argos review workflow-accept \
  --db ARCHIVE.sqlite --journal JOURNAL.sqlite --review-id REVIEW_UUID --input DECISION.json
```

Les fichiers d'entrée doivent être privés (`chmod 600`). Le JSON de décision
contient `id` (UUID stable à réutiliser lors d'un retry), `snapshot_sha256`,
`sources` (`kind`, `id`), `operator`, `decision`, `rationale` et `context`.
La commande `review journal-show` permet de relire cette décision vérifiée.
Une seconde soumission identique après succès est idempotente.

`workflow-show --expected-head SHA256` compare un checkpoint global conservé
séparément. `--history` inclut explicitement le snapshot privé figé, les requêtes,
complétions et annotations. Sans ce drapeau, la sortie omet les événements et
le snapshot complet. Ne pas publier cet historique ni les journaux privés.
Les commandes d'analyse ne démarrent pas de serveur et ne téléchargent rien.
Le modèle reste librement configurable ; l'alternative légère est `qwen2.5:0.5b`.

## Qualification locale

Le script `benchmarks/llm/qualify_review.py` réalise une seule inférence par
archive explicitement fournie, sans démarrer de daemon, télécharger de modèle
ni accepter une revue à la place de l'opérateur. Exemple, serveur déjà lancé :

```bash
PYTHONPATH=. .venv/bin/python benchmarks/llm/qualify_review.py \
  --archive crapi ARCHIVE.sqlite UUID --model qwen3:4b --port 11434 \
  --output "$HOME/.local/share/argos/qualification/m33"
```

Le dossier de sortie doit être privé (700) et hors du checkout. Un UUID neuf
sépare chaque campagne ; les sources sont hachées avant et après et ne sont
pas modifiées. Les requêtes et complétions restent dans le journal privé.

Le 25 novembre 2026, trois essais Qwen3 4B sur les archives M2.7.1 existantes
ont terminé à `ready` :

| Archive | Éléments critiques conservés | Temps fournisseur + validation | Tokens entrée / sortie |
| --- | ---: | ---: | ---: |
| crAPI | 8/8 | 7,412 s | 778 / 42 |
| DVWA | 7/7 | 1,458 s | 668 / 42 |
| Juice Shop | 8/8 | 1,532 s | 761 / 42 |

Les trois bases ont gardé leur empreinte fichier. Ces temps concernent les
appels explicites de cette qualification, pas la campagne des 75 inférences.
Le daemon a été arrêté ensuite. Aucun scan, aucune requête vers les cibles,
aucun téléchargement ni nouvelle décision humaine n'a été effectué.

Les résultats privés sont sous
`~/.local/share/argos/qualification/m33/73738784-433b-4f69-979b-737d89e3b8cc/` :
`reviews.sqlite`, `configuration.json`, `result-1.json` à `result-3.json`,
`summary.json`. Le répertoire parent conserve `server.log`, `execution.log`,
`launch-qualification.py` et les journaux de tests. Les anciennes baselines
et les traces historiques M3.2.1 restent inchangées.

Les fixtures de test sont indépendantes des attentes du modèle : elles forcent
une sélection qui omet les éléments critiques, des références invalides, des
timeouts, un modèle absent, une exception inattendue, une annulation et une
tentative orpheline. Elles couvrent aussi l'altération des preuves et du
journal, une archive valide modifiée, les checkpoints externes, les transitions,
la validation idempotente et l'interruption entre décision et rattachement.
Une fixture de 300 inconnues vérifie que le volet critique complet survit
même à leur exclusion du contexte compact. Le cycle CLI est testé sans réseau.

Les trois archives n'ont pas d'oracle expert : ces essais qualifient persistance,
liaison aux preuves et conservation des incertitudes, sans attribuer de score
de raisonnement au modèle. Les omissions du LLM subsistent dans sa sélection ;
le volet déterministe les rend visibles, sans prétendre les résoudre.
La revue ne renouvelle pas les observations historiques et ne mesure pas la
couverture actuelle des applications.

Le journal vérifie toute sa chaîne à la lecture ; les gros historiques et les
revues concurrentes nombreuses n'ont pas fait l'objet d'une mesure de charge.
Conserver séparément le checkpoint de revue et celui du Decision Journal
(`review journal-show --expected-head`) si des décisions hors workflow sont
ajoutées. Le stockage local doit être sauvegardé par l'opérateur ; la présence
des fichiers et les empreintes ne constituent pas une sauvegarde externe.

## Validation de livraison

Les 13 cas ciblés passent sous Python 3.12 et 3.14. La suite régulière finale
compte **1 246 réussites, 121 ignorés sous chaque interpréteur**. Les essais
hôte optionnels de reconnaissance/isolation/navigateur sont désactivés ;
ils ne sont pas une qualification ajoutée par cette revue hors ligne.
Ruff, formatage, Pyright, liens locaux et `git diff --check` passent.

Commandes exécutées :

```bash
.venv/bin/python -m pytest -q tests/test_review_workflow.py tests/test_review_workflow_cli.py
/tmp/argos-stabilization-py312/bin/python -m pytest -q tests/test_review_workflow.py tests/test_review_workflow_cli.py
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
# Pour chacun des deux interpréteurs, sans ARGOS_TEST_{NETWORK,ISOLATION,BROWSER,TOOL_REGISTRY}
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -q -o faulthandler_timeout=30
git diff --check
```

La branche `feat/m33-supervised-workflow` reste locale, sans merge ni push.
Aucun travail M3.4 n'a été commencé. L'agent autonome et la sélection d'actions
offensives restent non implémentés.

## Consolidation avant M3.4

Contrats et qualification revérifiés : les trois journaux historiques sont
intègres et correspondent toujours aux snapshots des archives crAPI, DVWA et
Juice Shop. Les fichiers du manifeste privé de clôture correspondent à leurs
empreintes. Aucun nouvel appel au modèle n'a été nécessaire. La suite régulière
repasse sous Python 3.12 et 3.14 : 1 246 réussites, 121 ignorés par interpréteur ;
Ruff, formatage et Pyright passent. Les limites de pertinence sémantique ci-dessus
restent applicables. Intégration fast-forward autorisée après ces validations ;
M3.4 sera développé sur une nouvelle branche sans publication implicite.
