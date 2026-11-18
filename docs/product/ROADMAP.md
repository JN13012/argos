# Argos — Roadmap de référence

État du dépôt vérifié le 18 novembre 2026. Cette page porte les statuts et la
priorité active. Le [scope](SCOPE.md) décrit le périmètre produit ; le
[plan web](WEB_PENTEST_PLAN.md) organise la réalisation ; le
[catalogue](WEB_CAPABILITIES.md) définit les capacités et preuves à construire.
Les documents des lots portent leurs tâches et bilans détaillés.

## Objectif et prochaine tâche

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
vérifier son empreinte et d’afficher son résultat expurgé.

**Prochaine étape côté navigateur : W4.3c, actions de formulaire et sessions.**
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
| Autres outils web | ZAP, Nuclei, SQLmap, ffuf et Katana sont des candidats ; aucun de leurs adaptateurs de mission n’est livré |
| Agent autonome / LLM | Architecture conçue, aucune boucle de mission LLM connectée |
| Restitution client | Premier export Markdown de la découverte et du contrôle existant ; rapport multi-familles à construire |
| OSINT / Nmap | CLI SIRENE livré ; Nmap en bibliothèque avec exécution contrôlée, qualification réelle encore ouverte |
| API et interface | Santé HTTP reliée au frontend ; aucune interface métier de mission active |
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
| W8 | Protocole au plan ; exécution à faire | Corpus versionné, témoins corrigés, jeux réservés et comparaison experte ; publier précision, omissions, autonomie, coûts et limites |
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
