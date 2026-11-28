# Argos — Roadmap de référence

État du dépôt vérifié le 27 novembre 2026. Cette page porte les statuts et la
priorité active. Le [scope](SCOPE.md) décrit le périmètre produit ; le
[plan web](WEB_PENTEST_PLAN.md) organise la réalisation ; le
[catalogue](WEB_CAPABILITIES.md) définit les capacités et preuves à construire.
Les documents des lots portent leurs tâches et bilans détaillés.

## Objectif et prochaine tâche

**Priorité active — [Recon V2](RECON_V2.md).**
M4.1 a préparé le corpus et M4.2a a reproduit le diagnostic sur archives.
M4.2b reste une qualification partielle sur fixtures bénignes et archives.
M4.2c a vérifié le parcours CLI SPA avec son état partiel et ajouté une vue
de restitution de l'incertitude. M4.2d consolide ces résultats et traite les
délimitations JavaScript ambiguës. L'intégration à main attend validation.
La campagne active des trois laboratoires historiques et les coûts natifs
par adaptateur restent non qualifiés. Le Skill Engine est reporté.

Première offre : **pentest web/API autonome, boîte noire externe depuis le CLI**.
La mission commence avec une URL ou un domaine, sans compte ni documentation.
Les comptes accessibles ou fournis enrichissent les tests. L’agent devra
explorer, choisir ses hypothèses, exécuter, vérifier et produire rapport/recontrôle
sans validation humaine entre les actions comprises dans sa configuration.

Le [premier rapport client W6](WEB_CLIENT_REPORT.md) est disponible en Markdown
à partir d’une exécution enregistrée, avec preuves, recontrôle et matrice de
couverture des 20 familles du catalogue Argos. La même matrice est disponible
en [JSON versionné](WEB_CLIENT_REPORT.md#export-json-de-la-couverture), avec
[comparaison hors ligne](WEB_CLIENT_REPORT.md#comparer-deux-exports) de deux
exports de la même exécution. Un [index des preuves HTTP](WEB_CLIENT_REPORT.md#index-des-preuves-http)
relie les reçus aux routes, navigations et contrôles enregistrés. La
[consultation d’un reçu](WEB_CLIENT_REPORT.md#consulter-un-reçu) permet de
vérifier son empreinte et d’afficher son résultat expurgé. La
[vérification d’un index archivé](WEB_CLIENT_REPORT.md#vérifier-un-index-archivé)
contrôle en une commande que l’index correspond aux preuves de l’exécution
dans la base privée. L’[export JSON des constats](WEB_CLIENT_REPORT.md#exporter-les-constats-pour-suivre-les-corrections)
fournit des identifiants stables, les preuves de la première confirmation
et le dernier recontrôle pour le suivi des corrections. La
[comparaison des constats](WEB_CLIENT_REPORT.md#comparer-les-constats-avant-et-après-un-recontrôle)
repère les changements d’état et les nouveaux recontrôles entre deux exports
de la même exécution. La [vérification groupée des exports](WEB_CLIENT_REPORT.md#vérifier-les-trois-exports-dun-rapport)
compare la couverture, les constats et l’index des preuves au même instantané
de la base privée, avant la remise du rapport.

**M2.7.1 validé localement : [fingerprinting et énumération consolidés](RECON_CONSOLIDATION.md)**,
après la [qualification M2.7](RECON_QUALIFICATION.md), sur
`feat/m27-recon-qualification`. Signaux génériques versionnés, calibration
partagée et arrêts explicites ; requalification 3.12/3.14 terminée avant livraison.
Les baselines M2.2 à M2.7 sont conservées. Intégration fast-forward et
publication de main autorisées pour M2.7.1 après validation, puis CI du SHA
poussé.

Les [fondations M3.1](M31_FOUNDATIONS.md) sont validées localement. Elles
couvrent le snapshot hors ligne (B), l'inventaire descriptif (C), le journal
opérateur (D) et la revue consultative compacte (E), après l'[audit
préalable](DECISION_ENGINE_AUDIT.md). Le moteur décisionnel autonome reste
non implémenté. [M3.2](M32_LOCAL_LLM_ANALYST.md) ajoute un analyste local
consultatif pour les missions archivées. Le [benchmark M3.2.1](M321_LOCAL_LLM_BENCHMARK.md)
est qualifié localement sur cinq modèles CUDA, avec des limites de pertinence
explicites et une recommandation consultative. Sa consolidation conserve durablement les traces privées et les modèles hors Git,
avec archivage complet des futurs essais ; intégré et publié sur main après
validations locales et CI verte. M3.3 est intégré sur main par fast-forward, avec CI verte :
[workflow de revue supervisée](M33_SUPERVISED_REVIEW.md), sans moteur autonome.
[M3.4](M34_MEMORY_ENGINE.md) est intégré sur main par fast-forward, avec
[CI verte](https://github.com/JN13012/argos/actions/runs/45694650557).
[M3.5-C.1](M351_DATA_ARCHITECTURE.md) centralise le stockage local et documente
sa migration.
[M3.5-E](M35_RETRIEVAL_BENCHMARK.md) qualifie localement FTS5, trois modèles
d'embeddings, RRF et trois moteurs exacts. La consolidation vérifie le
rejeu hors ligne, les licences et la séparation des installations Ollama.
Les choix du pilote restent provisoires. Les [fondations M3.5.1](KNOWLEDGE_ENGINE_SPEC.md)
implémentent le catalogue de sources et le stockage documentaire versionné et
cloisonné. M3.5.2 ajoute l'ingestion normalisée et trois découpages citables,
avec mesures sur le corpus MDN local. M3.5.3 ajoute les index SQL et FTS5
transactionnels et la recherche documentaire locale. M3.5.4 ajoute le cache
Float32, la recherche NumPy exacte et le routeur. V2 extractif et la maintenance documentaire ont été consolidés sur main en
M3.5.8. Le pilote génératif reste non qualifié.

**Dépendance des futurs parcours de session — W4.3c, formulaires et sessions.**
W4.3b apporte les redirections navigateur sous configuration v5 signée :
interception CDP de chaque saut, preuve avant remise, URL finale réelle et
plafonds. Le [lot W4.3](WEB_INTERACTIONS.md) et
[l'ADR](../architecture/adr/0002-browser-redirect-interception.md) portent les
contrats et limites. Les missions v1 à v4 gardent leurs représentations et
comportements ; v3/v4 continuent de refuser les 3xx au rendu. W4.3c doit ajouter
les actions de formulaire et les sessions anonymes puis identités séparées,
sans confondre une requête exécutée et une transaction métier vérifiée.

## Capacités disponibles et limites

| Capacité | État réel |
| --- | --- |
| CLI web | Configuration, activation, découverte HTML et navigateur (`browse`), arrêt/reprise explicite, `request`/`request-status`, status/report JSON, vérification et recontrôle du premier oracle |
| Runtime HTTP | GET/HEAD historique ; requêtes structurées anonymes v4 (GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE), méthodes/corps/en-têtes bornés, écritures explicites, tickets et preuves ; pas de sessions |
| Découverte HTML | Liens et paramètres observés, frontière persistante, raisons de refus et états partiels |
| Premier oracle web | Redirection externe pilotée par un paramètre découvert : référence, deux marqueurs et recontrôle ; impact métier à qualifier |
| Navigateur | Chromium → HTTP/TLS depuis le CLI ; redirections document/script/API en v5 avec preuve par saut, URL finale et liens DOM ; GET/HEAD, même origine, sans sessions |
| Reconnaissance par outils | [Pipeline Nmap → Gobuster → ffuf](WEB_RECON.md) validé localement sous Python 3.12/3.14 avec les vrais binaires ; énumération de chemins GET, extraction statique JavaScript/OpenAPI et provenance ; shell SPA distinct des soft 404, sans couverture universelle ; M2.1.1/M2.1.2 : registre administrateur, outils locaux isolés, `doctor`, lanceur et helpers permanents ; baseline locale renouvelée à découvertes identiques ; M2.2.1–3 : calibration SPA, inventaire web local et profils wordlists bornés, extraction statique priorisée et limites traçables ; qualification des profils et limites effectives documentées dans le lot recon (M2.2.4) |
| Cartographie réseau M2.3 | [Profils et inventaire TCP multi-hôtes explicites](NETWORK_RECON.md), validés sur fixtures et laboratoire TCP local IPv4/IPv6 ; mêmes jobs, preuves et worker isolé, sans expansion du scope ; limites et validation détaillées dans le lot |
| Fingerprinting M2.4 | [Identification passive et corrélation liées aux preuves](FINGERPRINTING.md), validées localement ; états et versions explicites, catalogue limité, aucun trafic ajouté par le moteur ; faux positifs/manques mesurés dans le lot |
| Cartographie applicative M2.5 | [Graphe hors ligne lié aux preuves](APPLICATION_MAPPING.md) : hôtes/services/applications, ressources, formulaires, API/méthodes/paramètres attestés ou déclarés, technologies, relations et consultation ; états et limites explicites, aucune nouvelle capacité active |
| Énumération contextuelle M2.6 | [Plans déterministes et couverture vérifiée](CONTEXTUAL_ENUMERATION.md), comparaison aux listes prédéfinies sur laboratoires locaux ; mêmes relais/workers et plafonds, aucun LLM ni expansion de scope |
| Qualification M2.7 | [Missions complètes comparées](RECON_QUALIFICATION.md) sur trois applications locales réelles, référentiels séparés ; validé localement sous 3.12/3.14 sur la branche, couverture limitée, variantes système absentes non qualifiées et aucune qualification universelle |
| Consolidation M2.7.1 | [Signaux génériques et calibration partagée](RECON_CONSOLIDATION.md), 6/7 technologies du référentiel commun reconnues ; quotas inchangés, anciennes projections conservées, versions et états partiels explicites |
| Fondations M3.1 | [Revue et contexte de mission](M31_FOUNDATIONS.md), qualifiés hors ligne sur trois archives ; journal des décisions explicites de l'opérateur |
| Mémoire consultative M3.4 | [Mémoire SQLite par UID/mission, recherche et contexte borné](M34_MEMORY_ENGINE.md), validé sur fixtures et trois archives, intégré sur main avec CI verte |
| Revue supervisée M3.3 | [Cycle persistant et validation opérateur](M33_SUPERVISED_REVIEW.md), qualifié hors ligne et sur trois archives via Ollama local ; intégré sur main et CI verte |
| Analyste local M3.2 | [Synthèse consultative sur preuves archivées](M32_LOCAL_LLM_ANALYST.md) via Ollama en boucle locale, avec références et états vérifiés |
| Autres outils web | ZAP, Nuclei, SQLmap et Katana restent des candidats sans adaptateur de mission livré |
| Agent autonome | Architecture conçue, aucune boucle d'exécution pilotée par un LLM |
| Restitution client | Premier export Markdown de la découverte et du contrôle existant ; rapport multi-familles à construire |
| OSINT / Nmap | CLI SIRENE livré ; Nmap réel exercé via le pipeline sur un laboratoire TCP local ; qualification externe/production encore ouverte |
| API et interface | M1.2/M1.3 : dashboard SOC responsive, recherche de missions, journal des transactions/preuves archivées et consultation locale en lecture seule des missions SQLite autorisées, ports Nmap, transactions HTTP et reçus vérifiés ; téléchargements de rapports explicitement configurés. Aucun lancement de mission depuis l’interface |
| Enum2Root / PromptLab | Références étudiées, sans intégration fonctionnelle complète |

**Argos n’effectue pas encore un pentest web complet.** Les nouveaux parcours
CLI relient réellement Chromium aux workers HTTP/TLS locaux et suivent une
page créée par JavaScript. Le bilan de validation W4.3b est détaillé dans le
[lot](WEB_INTERACTIONS.md#bilan-w43b) : 1 044 réussites sous chaque
interpréteur Python 3.12/3.14, dont 86 essais hôte activés. Ce bilan est une preuve
de régression/isolation datée, pas une mesure du taux
de failles détectées. Le corpus de 12 cas W1.2 est préparé, non exécuté.
Les résultats de CI distante ne sont pas revérifiés par cette mise à jour.

## Lots livrés et références

| Lot | Statut et référence |
| --- | --- |
| P0 | Validé localement ; [bilan de fiabilisation](FIABILISATION_P0.md) |
| P1.1–P1.4 | Livrés et qualifiés localement ; [exécution](EXECUTION_P1.md), [worker](WORKER_ISOLATION.md), [réseau](MISSION_NETWORK.md) |
| W1.1 / W1.3 | [Configuration](WEB_CONFIG.md) livrée ; [spécification HTTP](WEB_HTTP_EXECUTION.md) de référence |
| W1.2 | [Corpus préparé](../../benchmarks/web/README.md) ; images, témoins et notation encore à qualifier |
| W2.1–W2.3 | [Politique](WEB_HTTP_POLICY.md), [transport](WEB_HTTP_TRANSPORT.md) et [runtime HTTP](WEB_HTTP_RUNTIME.md) livrés et validés localement |
| W3.1–W3.2 | [CLI/découverte](WEB_CLI_DISCOVERY.md) et [oracle/recontrôle](WEB_OPEN_REDIRECT.md) livrés et validés localement |
| W4.1 | [Navigateur isolé](WEB_BROWSER_WORKER.md) livré et qualifié sur les fixtures décrites, sans ouverture aux missions CLI |

## Ordre de réalisation restant

| Lot | Statut | Livrable observable et critère de sortie |
| --- | --- | --- |
| W4.2a | Validé localement | Configuration v3, budgets et états navigateur ; anciennes configurations et signatures inchangées, aucun trafic ajouté |
| W4.2b | Validé localement | Relais vers le runtime HTTP, ticket par ressource, remise après commit et deadlines ; panne de preuve = aucune remise au navigateur |
| W4.2c | Validé localement | Commande `browse`, frontière DOM/API, provenance et vues ; chaîne HTML → JS → API → lien dynamique sur HTTP/TLS réel, avec arrêt/reprise testés |
| W4.3a | Validé localement | Requêtes structurées anonymes, v4 signée, limites et écritures explicites, preuves et consultation CLI ; HTTP/TLS, arrêt et récupération sans replay |
| W4.3b | Validé localement | Interception de chaque redirection navigateur, URL visible exacte, périmètre, cycles, budgets et preuve par saut |
| W4.3c | À détailler | Actions de formulaire et sessions anonymes puis identités optionnelles séparées ; parcours, reprise et nettoyage sans fuite |
| W5.1 + W6 initial | [Rapport et matrice par famille validés localement](WEB_CLIENT_REPORT.md#matrice-de-couverture-w51) | Restituer les observations, les contrôles et les lacunes par famille. Le registre détaillé des cas reste à étendre. |
| W5.2–W5.3 + W6 | À détailler | Premier ensemble anonyme multi-familles puis accès/sessions/API selon les identités disponibles ; témoins corrigés, effet reproduit et rapport utile |
| W7 V0 | À détailler après les premiers cas W5/W6 | Boucle autonome sur un petit ensemble déjà vérifié ; hypothèses, choix, observation, validation, reprise et rapport sans intervention intermédiaire |
| W5.4–W5.6 + W6/W7 | À détailler | Fichiers, traitements serveur, SSRF/XXE, logique métier et approfondissements ; enrichir le catalogue et l’agent avec mesures par famille |
| W8 | [M2.0/M2.0.1 : évaluateur minimal et première mesure Juice Shop isolée localement](../../benchmarks/web/README.md#m201--première-mesure-locale-23-novembre-2026) ; isolation complète à qualifier | Image OCI figée, états avant/après, mesures distinctes recon/constats/delta officiel, exports JSON/HTML et filtre testé ; corpus complet, témoins corrigés et comparaison experte restent à faire |
| W9 | À faire après W8 | Livraison opérable, installation/secrets, rétention, sauvegarde/restauration, support et pilotes clients ; périmètre annoncé conforme aux capacités démontrées |

W6 et l’évaluation accompagnent chaque capacité. W7 n’attend pas un catalogue
exhaustif ; son premier périmètre reste limité aux capacités réellement
vérifiées. Préparer un lot dépendant ne le déclare pas exécutable. Une nouvelle
intégration d’outil s’inscrit dans le cas W5 concerné, avec sa qualification,
sans créer un programme concurrent.

## Travaux complémentaires et extensions

- **W0/P1.5** : qualification Nmap réelle, installation et revue du socle.
  Les contrôles nécessaires à une capacité web restent obligatoires ; le
  complément Nmap ne bloque pas une tranche HTTP indépendante.
- **P2 API/UI** : après le parcours CLI validé. Réutiliser les mêmes services,
  ajouter identités, accès aux missions et séparation des données ; requis
  avant une offre en libre-service multi-utilisateur.
- **A1–A5** : noms historiques des fonctions agent. Connaissance/outils/état
  correspondent à W1–W6, autonomie à W7 et mesure à W8. Aucun second backlog.
- **Extensions produit** : OSINT élargi, infrastructure/AD, cloud, DEFEND/GRC,
  sécurité des LLM et délégation multi-agent après la première mission web
  autonome mesurée. Les fondations existantes restent conservées.

## Sens des statuts

- `Préparé` : résultat, dépendances et critères écrits ; pas une implémentation.
- `En cours` : travail d’implémentation effectivement commencé.
- `Validé localement` : code et essais indiqués dans le lot ; limites déclarées.
- `Qualifié sur ...` : environnement et protocole précisément nommés, jamais
  qualification universelle déduite d’une fixture.
- `Bloqué` : raison et dépendance explicites ; ne signifie pas « sûr » ou « terminé ».

À chaque livraison : mettre à jour la ligne concernée, le bilan du lot et les
contrats ou références affectés. Les critères professionnels et métriques
restent au [plan web](WEB_PENTEST_PLAN.md), le contrat de restitution au
[lot rapport client](WEB_CLIENT_REPORT.md). Les seuils proposés ne constituent pas
une certification de niveau senior ni une promesse commerciale déjà tenue.


## M3.5 — Connaissances et RAG

| Étape | Statut | Porte d'acceptation |
| --- | --- | --- |
| M3.5.1 Fondations | Implémentées dans main, qualification locale | Identité et permissions, cycle de vie, intégrité et reprise transactionnelle sous Python 3.12 et 3.14. |
| M3.5.2 Ingestion et fragments | Implémentés dans main, qualification locale | Migration SQLite v2, trois formats et stratégies, repères de citation, transactions et mesures sur corpus local. |
| M3.5.3 SQL exact et FTS5 | Implémentés dans main, qualification locale | Migration v3, retraits transactionnels, cloisonnement, citations, corpus historique MDN et charge de 100 000 fragments. |
| M3.5.4 Embeddings et NumPy | Implémentés dans main, qualification locale | Migration v4, cache par collection et espace, reprise, MDN historique, abstention calibrée, repli lexical et 100 000 vecteurs synthétiques. |
| M3.5.4.1 Performance vectorielle | Implémentée dans main, qualification locale | Vue NumPy par génération, lectures concurrentes, retrait et mesures 512D et 768D jusqu'à 100 000 vecteurs. |
| M3.5.5 Contexte et revue V2 | Implémentés dans main, qualification locale limitée | Assemblage et restitution extractive, validation des citations, compatibilité V1, interruption et mesures sur les deux runtimes Ollama. |
| M3.5.6 Qualification du pilote | [Exécutée localement](M356_RAG_EVALUATION.md), pilote génératif non accepté | 115 cas appariés et trois archives réelles. Gain RAG, absence de gain mémoire et portes de qualité générative manquées. |
| M3.5.6.1 Fiabilité de l’analyse | [Exécutée localement](M3561_RAG_RELIABILITY.md), pilote génératif non accepté | Appui typé et abstention stricte. Les verdicts utiles et la précision des citations reculent sur le jeu de stress indépendant. |
| M3.5.6.2 Appui par proposition | [Exécuté localement](M3562_PROPOSITION_VALIDATION.md), pilote génératif non qualifié | V2 déterministe résout 5 des 11 cas répondables, tous exacts. Les questions libres, la précision des citations et l’abstention restent à qualifier. |
| M3.5.7 Maintenance documentaire | [Livrée et qualifiée localement](M357_KNOWLEDGE_MAINTENANCE.md) | Obsidian sur fixtures, lots transactionnels et synchronisation publique simulée. Fournisseurs réels reportés. |
| M3.5.8 Consolidation | Consolidation intégrée dans main, [bilan local](M358_KNOWLEDGE_CONSOLIDATION.md) | Parcours extractif complet, reprise des schémas v1 à v6, non-régression V1 et contrôles de confidentialité. Le pilote génératif reste non qualifié. |
| M3.5.9 Qualification intégrée | [Bilan local](M359_WORKFLOW_QUALIFICATION.md) | Intégrité et comparaison A–F sur trois archives, reprise sur fixtures et anomalies de restitution. |
| M3.5.10 Fiabilité intégrée | Clôture technique sur main, [bilan local](M3510_WORKFLOW_RELIABILITY.md). Utilité consultative encore ouverte | Persistance privée V2, cycle de tentative, comparaison avant/après et diagnostic de sélection. |

## Dépendances M3 et W0–W9

| Priorité | Dépendance et livrable |
| --- | --- |
| P0 | M3.5.9 s'appuie sur W0–W4 livrés, les exports W6, et M3.1–M3.5.8. W1.2 et W8 fournissent la discipline de mesure indépendante. W4.3c reste hors du chemin critique de cette qualification. |
| P1 | M3.5.10 traite les ruptures de restitution et de suivi des échecs M3.5.9. Les compléments W0/P1.5 concernent les chemins effectivement mobilisés. |
| P2 | Consolider les référentiels W1.2/W8 et la restitution W6. Les parcours authentifiés de W5.3 dépendent de W4.3c. W7 reste une cible dépendante de W5/W6 vérifiés et d'un protocole W8 gelé. |
| P3 | Skill Engine reporté pendant Recon V2. Réexamen après qualification de la reconnaissance et si la réutilisation des workflows consultatifs ou de restitution est démontrée. Réutiliser les évaluateurs existants. |
| P4 | Conditionner le Learning Engine à un historique comparatif, à l'évaluation indépendante et à une promotion humaine réversible. W9 dépend de W8 et de la qualification d'exploitation. |
