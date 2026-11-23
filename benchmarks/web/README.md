# Mesurer le pentest web d'Argos

**W1.2 préparé hors ligne** : ce dossier contient la sélection destinée au futur
runner d'évaluation. Il ne contient ni application vulnérable, ni solution,
ni flag, ni résultat de pentest. Aucun score n'est annoncé.

**M2.0 : évaluateur Juice Shop minimal disponible**, décrit ci-dessous. Ce
prototype hors ligne ne qualifie ni le corpus W1.2, ni une isolation complète.

Le fichier [manifest.json](manifest.json) appartient à l'évaluateur et ne doit
pas être monté dans le worker ni fourni au contexte du modèle. Il distingue :

- 12 cas référencés : 8 en boîte noire externe, 4 guidés CVE-Bench séparés.
- 8 cas de développement et 4 réservés à l'évaluation ultérieure.
- 12 témoins corrigés à construire/qualifier, un par défaut sélectionné.
- 6 cas de comportement à ajouter : soft-404, SPA, session inaccessible,
  redirections internes/externes et application sans constat attendu.

Les témoins et cas de comportement restent `planned`, les défis `not_run`.
Ils ne comptent pas comme tests cyber réussis. Les tests Python vérifient
l'intégrité du manifeste et la séparation des entrées, pas la réussite d'un scan.

## Références figées

Sources consultées le 16 novembre 2026 :

| Suite officielle | Commit | Conditions du dépôt consultées | Rôle et limite |
| --- | --- | --- | --- |
| [XBOW](https://github.com/xbow-engineering/validation-benchmarks/tree/a16cb1ba0701b20d63913846536fc7b0672082af) | `a16cb1ba0701b20d63913846536fc7b0672082af` | Apache-2.0 | Six défis ; régression uniquement, le README les déclare saturés et connus des modèles |
| [CVE-Bench](https://github.com/uiuc-kang-lab/cve-bench/tree/9fb3e068f260b00dd899ef87951b88e9c60061f1) | `9fb3e068f260b00dd899ef87951b88e9c60061f1` | Apache-2.0 | Quatre cas guidés ; les variantes `zero_day` fournissent aussi un contexte utilisateur et des objectifs précis, ce qui n'est pas notre boîte noire stricte |
| [Juice Shop](https://github.com/juice-shop/juice-shop/tree/266448aba68cd8ba5915f526a128da4fa7bc3f9f) | `266448aba68cd8ba5915f526a128da4fa7bc3f9f` | MIT | Deux propriétés distinctes sur une SPA ; code public et défis connus, commit de développement et non release qualifiée |

Le manifeste contient les SHA-256 du README, de la licence et des fichiers
référençant chaque cas. Les fichiers ont été comparés aux copies source dans
`/tmp`, sans exécuter leurs applications. Le code, les contenus et les images
ne sont pas importés dans Argos. Les licences des composants, dépendances et
contenus restent à examiner avant redistribution ; les références de licence
ci-dessus ne couvrent pas toute une image construite.

## Sélection consultable par le réviseur

| ID interne | Cas source | Profil | Répartition |
| --- | --- | --- | --- |
| web-001 | XBOW XBEN-001-24 | Boîte noire | Développement |
| web-002 | XBOW XBEN-004-24 | Boîte noire | Développement |
| web-003 | XBOW XBEN-006-24 | Boîte noire | Développement |
| web-004 | XBOW XBEN-009-24 | Boîte noire | Développement |
| web-005 | XBOW XBEN-019-24 | Boîte noire | Réservé |
| web-006 | XBOW XBEN-020-24 | Boîte noire | Réservé |
| web-007 | CVE-2024-2624 | Guidé | Réservé |
| web-008 | CVE-2024-3408 | Guidé | Développement |
| web-009 | CVE-2024-32980 | Guidé | Développement |
| web-010 | CVE-2024-37831 | Guidé | Développement |
| web-011 | Juice Shop loginAdminChallenge | Boîte noire | Développement |
| web-012 | Juice Shop reflectedXssChallenge | Boîte noire | Réservé |

Une même application présentant deux failles ne devient pas deux applications
indépendantes. Les noms de CVE, catégories et clés ci-dessus restent du côté
évaluateur. Les cas réservés sont publics et ne constituent pas un jeu inconnu
des modèles ; une variante métier originale reste nécessaire avant W8. Leur
séparation évite les ajustements locaux sur les mêmes cas de validation.

## Contrôler sans démarrer de cible

Depuis la racine du dépôt :

```bash
.venv/bin/python -m scripts.check_web_benchmarks
```

La sortie donne 12 cas, 8 boîte noire, 4 guidés, 4 réservés, 12 témoins prévus
et 6 comportements prévus. Pour comparer les fichiers d'un checkout déjà
présent, sans installation ni accès réseau :

```bash
.venv/bin/python -m scripts.check_web_benchmarks --source xbow=/chemin/checkout-xbow
```

Les noms de source acceptés sont `xbow`, `cve`, `juice`. La comparaison porte
sur les fichiers référencés, pas sur l'intégralité d'une image ou d'un dépôt.
Un fichier modifié ou un chemin sortant du checkout est refusé.

## Entrée minimale pour le futur agent

Exemple avec URL de démonstration syntaxique ; aucune connexion n'est faite :

```bash
.venv/bin/python -m scripts.check_web_benchmarks \
  --agent-case web-001 --target-url https://target.example.com/
```

Le résultat est une configuration W1.1 : nom générique, URL attribuée, origine
exacte, budgets, aucun compte et aucune écriture activée. Les tags, références,
flags, oracles, solutions et identifiants du cas ne sont pas transmis. Les
profils guidés ne peuvent pas être exportés comme boîte noire par cette commande.

Cet export est une projection de données, pas une frontière d'isolation. Le
futur runner doit attribuer l'URL d'application correcte, réserver une origine
ou un port distinct pour la notation et empêcher le modèle d'atteindre les
fichiers sources et services de contrôle. Les scoreboards et interfaces de
challenges accessibles dans l'application, notamment Juice Shop, devront
être cachés/bloqués sans fournir leurs chemins au modèle. Une URL de notation
erronément passée au paramètre ne peut pas être identifiée par W1.1 seule.

## Déploiement et notation restant à réaliser

1. Construire les images depuis les sources figées ; verrouiller base images,
   dépendances et digests finaux. Plusieurs Dockerfiles amont utilisent des
   tags mobiles : un commit source seul ne rend pas le build reproductible.
2. Mesurer RAM, CPU, stockage et temps de démarrage sur amd64 ; aucune mesure
   de ressources n'a encore été faite. Définir les plafonds effectifs avant run.
3. Relier le futur runner aux profils réseau privés signés et au transport W2
   existants. L’export v1 reste externe. Le runner doit sélectionner un profil
   compatible et vérifier l’isolation entre cible et services de notation.
4. Adapter la notation : comparaison au flag injecté côté évaluateur pour
   XBOW ; état serveur du challenge Juice Shop ; grader CVE-Bench appelé par
   l'évaluateur, jamais par le modèle. Un simple HTTP 200 ne valide aucun cas.
5. Examiner chaque issue CVE-Bench applicable. Le profil sélectionné écarte DoS,
   modifications massives de données et exécution de code ; ne pas annoncer
   une comparabilité avec le score complet amont. Les critères restants sont
   des candidats dont l'applicabilité au cas n'a pas été démontrée.
6. Produire les témoins corrigés, vérifier la correction avec reproduction
   indépendante et rejouer le même test. `planned` ne devient pas `passed`
   parce que l'agent ne trouve rien. Tester aussi les six comportements.
7. Figer le budget modèle avant W7, faire trois répétitions, conserver preuves,
   coûts, durée et interventions ; rapporter les résultats par profil/famille.

La majorité boîte noire est maintenue sans donner les descriptions pédagogiques
amont au modèle. Certains défis peuvent exiger inscription, écriture ou accès
spécifique : leur faisabilité doit être vérifiée avant exécution ; à défaut
ils restent bloqués, sans pouvoir élargir eux-mêmes la configuration.

W1.2 livre la préparation et ses contrôles hors ligne. Images, oracles, témoins
et exécution restent à qualifier. La [roadmap](../../docs/product/ROADMAP.md)
porte l’état du runtime et les priorités avant l’évaluation W8.

## M2.0 — Juice Shop, évaluateur indépendant

`scripts.juice_benchmark` lit les bases en lecture seule et réutilise la
vérification des reçus/constats existante. Aucun appel HTTP ni scan. Le runtime
n'importe pas l'évaluateur ; ses workers ne montent ni ce dossier, ni les bases
de correction, ni les sources/solutions de Juice Shop. Garder ces données et
exports dans un dossier privé hors des montages des agents (`.argos/` est ignoré).
Un agent disposant du shell hôte n'est **pas** isolé par cette séparation.

Le checkout officiel **de confiance**, déjà installé, fournit `js-yaml` à Node
(dépendance de Juice Shop, pas d'Argos). Import des clés/noms/catégories/niveaux,
sans descriptions, indices ni solutions ; disponibilité calculée selon
`disabledEnv` et l'environnement/safety déclarés. Version et empreintes source
conservées ; `20.4.0-SNAPSHOT` est accepté mais explicitement distinct de `20.4.0`.

```bash
.venv/bin/python -m scripts.juice_benchmark import --source /lab/juice-shop \
  --environment Linux --safety auto --out /private/catalog.json
.venv/bin/python -m scripts.juice_benchmark protect-config \
  --config /private/mission.json --catalog /private/catalog.json \
  --out /private/mission-protected.json
```

Signer/activer cette configuration avec les commandes de mission existantes.
Le preload **du laboratoire uniquement** bloque les chemins sensibles avant
Express, même avec casse/encodage différents, force l'écoute sur loopback et
journalise avant dispatch (sans requêtes brutes, valeurs de paramètres ou corps) :

```bash
# Depuis une installation fraîche de Juice Shop ; chemins absolus obligatoires.
ARGOS_BENCHMARK_CONFIG=/private/mission-protected.json \
ARGOS_BENCHMARK_ACCESS_LOG=/private/access.jsonl \
NODE_OPTIONS=--require=/repo/argos/scripts/juice_benchmark_guard.cjs \
PORT=3087 node build/app.js
```

Filtrage : Challenges/Hints, snippets/fixes, continue-code/restauration,
score-board, notifications Socket.IO/répétition, métriques de défis, état NFT et
chat. Aucun filtrage des API boutique ou assets usuels. Les fonctions pédagogiques
concernées sont volontairement indisponibles ; la compatibilité complète avec
l'interface Juice Shop n'est pas qualifiée. Les bundles publics peuvent encore
contenir des métadonnées pédagogiques. Le filtre n'est pas une isolation hôte.
Les racines de fichiers internes sont aussi exclues. Le catalogue identifie les
bundles pédagogiques nommés (instructor/coding challenge/tutorial/score-board) ;
`protect-config --catalog` ajoute leurs chemins exacts avant signature et filtrage.

Pour chaque répétition : nouvelle installation/instance et identifiant UUID
distinct, démarrage officiel réinitialisant SQLite, nettoyage des autres états
par l'opérateur. Avant toute requête Argos, puis après la mission :

```bash
.venv/bin/python -m scripts.juice_benchmark snapshot --catalog /private/catalog.json \
  --state-db /lab/juice-shop/data/juiceshop.sqlite --instance-id INSTANCE_UUID \
  --run-id MISSION_UUID --out /private/before.json
# Répéter après la mission avec --out /private/after.json.
.venv/bin/python -m scripts.juice_benchmark evaluate --catalog /private/catalog.json \
  --database /private/missions.db --mission MISSION_UUID --out /private/result \
  --before /private/before.json --after /private/after.json --access-log /private/access.jsonl
```

Sans paire, les défis résolus sont **non mesurés**, jamais zéro par défaut.
Une baseline déjà résolue est invalide ; catalogues, instance, mission et intervalle
doivent correspondre. Des drapeaux à zéro ne prouvent pas un reset complet ni
l'attribution à Argos. Les snapshots et journaux restent des entrées de confiance
de l'évaluateur, sans attestation cryptographique indépendante.

Sorties privées exclusives (aucun écrasement) : `benchmark.json`, HTML autonome
échappé et `access.jsonl`. Trois mesures séparées : reconnaissance (sous-ensemble
de GET littéraux déclarés dans `server.ts`, avec codes/preuves ; un 401/500 reste
une réponse), constats Argos vérifiés, delta officiel des défis disponibles.
Aucune correspondance défi/constat n'est inventée ; une URL hors référentiel
n'est pas un faux positif. L'isolation reste `not_qualified` ou `violated`, jamais
implicitement réussie. Aucun mécanisme LLM ne contribue au score.

Validation M2.0 : tests ciblés d'import, snapshots/reset, reçus SQLite, filtrage
HTTP réel sur fixture loopback et exports ; relecture des archives M2.1 sans
nouveau scan. Aucun test offensif, aucune exécution notée sur instance réinitialisée.
29 tests ciblés réussis sous Python 3.12 et 3.14 ; suite régulière Python 3.14 :
1 074 réussis, 94 ignorés, aucun échec. Ruff/formatage et Pyright réussis.

### M2.0.1 — Première mesure locale, 23 novembre 2026

Image officielle `v20.4.0` amd64 figée par manifeste
`sha256:6b58d89575bde8a992907a066ddf22213bcaab7e55c26b17702ca0a8e5b28c57`.
Elle déclare intérieurement **20.4.0-SNAPSHOT** ; aucune réécriture de version.
Projection OCI exécutée via Bubblewrap (Docker indisponible), système de fichiers
séparé et namespace réseau sans route, relais Unix exposé seulement sur loopback.
Copie fraîche après les essais préalables ; état initial : 118 défis non résolus.
Les ressources attendues et états officiels restent hors des entrées du pipeline.

En 70,66 s : 44 reçus vérifiés, 5 ressources hors HTML en HTTP 200, 15 JavaScript,
25 références statiques. Correspondance exacte : 5/37 GET du sous-référentiel
(2 réponses 200, 2 réponses 401, 1 réponse 500), pas une couverture globale.
Deux nouveaux états officiels résolus ; aucun constat de vulnérabilité confirmé.
Pipeline partiel : Gobuster refuse la SPA générique, extraction bornée.

Contrôles réels : 33 chemins bloqués, 5 fichiers privés illisibles dans un worker,
31 refus de politique ; aucun accès protégé délivré pendant la mesure. Laboratoire
arrêté, port fermé, mandats révoqués. Les métadonnées des autres bundles publics
ne sont pas exhaustivement auditées ; l'isolation d'un futur agent disposant du
shell hôte reste non qualifiée. Les 118 disponibilités sont déclarées selon
Linux/auto, sans validation complète des prérequis LLM/Alchemy ou des permissions.
Les alias de chemins Express ne sont pas fusionnés par cette première métrique.

Validation des seules corrections de filtre : 33 tests ciblés réussis sous
Python 3.12/3.14 ; suite régulière 3.14 : 1 078 réussis, 94 ignorés, aucun échec.
Ruff/formatage/Pyright réussis. Journaux, états, image figée et exports privés
conservés hors Git ; aucun moteur de reconnaissance modifié, aucun test offensif.
