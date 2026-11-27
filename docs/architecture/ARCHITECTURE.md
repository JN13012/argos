# Argos — Architecture

État des sources au 17 novembre 2026. Monolithe modulaire, package Python unique,
frontend React/TypeScript/Vite séparé pour son outillage.

Priorité de réalisation : [pentest web autonome depuis le CLI](../product/WEB_PENTEST_PLAN.md).
Le parcours cible commence par une URL/domaine sans compte ni documentation.
La découverte anonyme est obligatoire ; les comptes enrichissent la couverture.
La configuration web immuable est livrée : JSON, normalisation, périmètre
hors ligne et liaison signée aux missions. Une mission web n'a pas de réseau
IP implicite ; sa configuration est stockée dans une table additive. L'action
HTTP générique reste refusée ; seul le runtime HTTP interne suit les tickets. Voir le
[contrat W1.1](../product/WEB_CONFIG.md). Le
[transport W1.3](../product/WEB_HTTP_EXECUTION.md) précise le chemin cible :
résolution supervisée dans le runtime, IP épinglée, worker HTTP fixe, TLS vérifié
et preuves expurgées. Les [contrats v2 et la politique hors ligne W2.1](../product/WEB_HTTP_POLICY.md)
sont livrés. Le [transport isolé W2.2](../product/WEB_HTTP_TRANSPORT.md) et le
résolveur supervisé sont qualifiés sur endpoints locaux. Le
[runtime W2.3](../product/WEB_HTTP_RUNTIME.md) ajoute tickets et compteurs
persistants, preuves expurgées, audit et récupération sans renvoi implicite.
Le [CLI W3.1](../product/WEB_CLI_DISCOVERY.md) réalise la découverte HTML
anonyme avec frontière persistante, capture atomique et arrêt/reprise.
Le [vérificateur W3.2](../product/WEB_OPEN_REDIRECT.md) lie référence, deux
sondes à marqueurs, sources de découverte et recontrôle. Les constats sont
issus de cet oracle vérifié, jamais du seul statut HTTP ou du modèle.
Le [worker navigateur W4.1](../product/WEB_BROWSER_WORKER.md) exécute du
JavaScript dans un navigateur sans réseau direct ; son relais Unix borne les
ressources et refuse les autres origines. Le
[relais de mission W4.2b](../product/WEB_BROWSER_RUNTIME.md#bilan-dimplémentation-w42b)
le raccorde au runtime HTTP signé : ressource et reçu liés atomiquement,
réponse remise après commit, limites v3, capture DOM persistante et récupération
sans replay. L'entrée `BrowserNavigation` exige une route HTML déjà vérifiée.
Les échanges HTTP/TLS locaux et le nettoyage navigateur/HTTP après crash sont
qualifiés. W4.2c expose `browse`, relève les API et alimente la frontière HTTP
avec les liens DOM. Des marqueurs liés aux captures dans le run et une
provenance optionnelle sur les nouvelles routes rendent cette expansion
idempotente, transactionnelle et comptée dans le quota de preuves. Les vues
restent en lecture seule ; `browse --resume` adopte seulement les travaux
jamais réservés, sans rejouer les navigations interrompues.
Le [transport structuré W4.3a](../product/WEB_INTERACTIONS.md) ajoute un DTO
`StructuredWebRequest`, une configuration v4 explicitement signée et les
commandes `request`/`request-status`. Le même runtime applique méthodes, corps,
en-têtes et effets permis avant DNS puis lancement ; le worker génère lui-même
Host, Content-Length et encodage. Les entrées privées sont versionnées et les
reçus expurgés v2 lient tailles/empreintes. Aucun retry d’écriture, suivi de 3xx HTTP direct
ou cookie n’est ajouté. Les sessions multi-rôles et services de mission restent
à construire.

[W4.3b](../product/WEB_INTERACTIONS.md#bilan-w43b) ajoute une configuration v5
signée et un pilote CDP Fetch, décrit dans l'[ADR 0002](adr/0002-browser-redirect-interception.md).
Il remplit ou bloque chaque requête sans continuer dans le réseau Chromium.
Les ressources JSON v2 lient identifiant de saut, parent, profondeur, destination
privée et empreinte du reçu. La capture v2 lie l'URL finale réelle à un document
offert ; le rapport ne présente que son empreinte. Chaque saut repasse par le
runtime HTTP et ses contrôles, y compris DNS/TLS et révocation. Une origine
exacte reste requise ; les cibles auxiliaires limitent ce rendu. Les anciens
pilotes/configurations et reçus restent lisibles, sans réécriture ni DDL nouvelle. Le
contrôle IP/port est complété par les contrôles d'origine, URL et méthodes du
médiateur et de la politique HTTP, même lorsque plusieurs origines partagent
une adresse IP.

## Architecture actuelle

```text
argos/
├── __main__.py, cli.py       CLI OSINT, web, revue et connaissances
├── backend/
│   ├── api/                 Santé HTTP et résultats archivés en lecture seule
│   ├── core/                Missions, scope, signatures, politiques et audit
│   ├── intel/osint/         Modèles, SIRENE, découverte, SQLite et rapports
│   ├── attack/pentest/      Plans, Nmap, jobs supervisés, preuves, orchestration
│   ├── attack/recon/        Pipeline CLI Nmap, HTML, Gobuster et ffuf via relais contrôlé
│   ├── attack/web/          Runtime HTTP, navigateur, reçus et restitution W6
│   ├── attack/review/       Snapshot, journal, revue V1/V2 et mémoire SQLite
│   ├── knowledge/           Collections et passages versionnés, recherches SQL/FTS5/NumPy
│   └── consultation/        Budgets V2, assemblage, validation et sélection extractive
├── osint/                   Réexportations de compatibilité des modèles
└── frontend/                Interface de consultation des résultats
```

ATTACK P1 est une bibliothèque locale avec vérification des missions signées,
reconnaissance en deux phases et preuves vérifiées. Aucun endpoint métier ni
agent n’appelle encore ce moteur. Les runners synchrones historiques ne sont
pas le point d’entrée à exposer au futur harness. Les
[limites d’exécution](../product/PENTEST_P135_HARDENING.md) restent ouvertes.

La restitution web et la revue lisent des archives privées. Le snapshot vérifie
les projections et les reçus. Le journal de revue fixe la vue examinée et la
décision de l’opérateur. V2 combine les unités vérifiées du snapshot avec une
mémoire facultative et des passages documentaires explicitement autorisés. La
mémoire est cloisonnée par UID et mission. Les collections ont leurs propres
révisions. Ces magasins sont relus indépendamment. Le journal V2 conserve une
empreinte de la restitution, dont le contenu complet est transitoire.

Ollama local peut sélectionner des références dans un contexte borné. Le
workflow de revue demeure consultatif. L’API de résultats expose les archives
configurées en lecture seule. Le [lot M3.5.9](../product/M359_WORKFLOW_QUALIFICATION.md)
documente les garanties et les limites vérifiées.

## Cible autonome

```text
Mandat + limites de mission
          ↓
État persistant ↔ Planificateur / agent ↔ Connaissance versionnée
          ↓ propositions typées
Registre de capacités → Politique déterministe → Worker isolé
          ↑                                      ↓
          └──── Vérification ← Observations + preuves
                              ↓
                      Rapport et recontrôle
```

Ce schéma est une cible. Le catalogue étendu, la boucle agentique, la reprise
du plan de mission complet restent à construire. Le worker réseau est intégré
en bibliothèque et qualifié localement ; le
[pipeline de reconnaissance](../product/WEB_RECON.md) exerce désormais les vrais
binaires Nmap, Gobuster et ffuf en laboratoire local. Sa qualification sur des
cibles externes reste ouverte. Le choix
d’un agent existant,
dont Hermes, ou d’un moteur propre passe par une évaluation. Aucune brique
adoptée ne peut contourner les permissions du runtime Argos.

Une mission peut autoriser à l’avance plusieurs étapes : l’autonomie ne dépend
pas d’une validation humaine de chaque appel. Les décisions hors mandat et les
conditions d’arrêt restent gérées indépendamment du modèle.

## Vocabulaire et boucle de mission cible

Les termes suivants fixent les responsabilités dans Argos. D'autres projets
peuvent employer « moteur », « agent » et « runtime » autrement.

| Élément | Responsabilité |
| --- | --- |
| LLM | Proposer un plan ou une action structurée à partir de l'objectif, des observations et des capacités disponibles ; interpréter les résultats |
| Agent | Ensemble logiciel associant le modèle, ses instructions, son contexte, sa mémoire et une boucle de décision orientée vers l'objectif |
| Moteur de mission | Coordonner les étapes, les dépendances, les états persistants, les reprises et les conditions de fin ; il peut suivre un workflow déterministe ou consulter un agent |
| Runtime d'exécution | Appliquer les permissions et budgets, gérer la file, lancer les workers, surveiller les processus, interrompre et conserver les preuves |
| Capacité et adaptateur | Décrire une action avec des paramètres typés et traduire cette action vers une fonction, un script, un binaire ou une API |

Ces responsabilités peuvent être regroupées dans un même processus au début.
Elles ne nécessitent pas cinq services distincts. Dans le code actuel,
`ExecutionManager` est une partie du runtime et `AdaptiveReconOrchestrator`
coordonne un workflow déterministe à deux phases ; aucun des deux ne constitue
un agent LLM.

Exemple cible : une mission autorise la reconnaissance et l'identification de
services sur une IP de laboratoire. Le modèle propose un appel structuré
`identify_services(target, ports)`. Le moteur rattache l'appel à la mission ;
le runtime valide le mandat, les paramètres, les budgets et la cible.
L'adaptateur construit les arguments de l'outil et le worker l'exécute.
Le parseur transforme la sortie en observations, les preuves sont enregistrées,
puis l'agent reçoit le résultat ou le motif du refus et choisit la suite.

Le nom `identify_services` illustre un contrat futur, pas un outil déjà exposé.
Aujourd'hui, `AuthorizedNmapRunner.prepare()` construit déjà des arguments
contrôlés et `ExecutionManager` lance Nmap avec `shell=False`.

Un script est donc une implémentation possible d'une capacité, parmi d'autres.
La boucle d'agent n'est pas limitée à une liste de scripts prédéfinie : elle
peut adapter son plan aux observations. La génération de nouveaux scripts
serait une capacité supplémentaire à concevoir et à isoler, avec ses propres
permissions ; elle n'est pas incluse dans le périmètre actuel.

Le modèle choisit parmi les possibilités proposées, sans accorder lui-même
une permission. Les décisions de politique, les quotas et les conditions
d'arrêt restent déterministes. Une observation d'outil n'est pas encore un
constat vérifié ; les conclusions du rapport doivent renvoyer aux preuves.

## Contrats et stockage

Les capacités métier restent appelables sans agent. L’orchestrateur adaptatif
dépend du protocole typé `ReconExecutionManager`, pas d’une implémentation de
test. Les imports `argos.osint.models` réexportent explicitement les classes
canoniques sans dupliquer leur logique.

`pyproject.toml` et `uv.lock` pilotent le Python ; le frontend conserve son
`package.json` et son lock npm. SQLite sert aux observations et aux registres
locaux. Le registre distingue une capacité active et un cache terminal borné ;
l'état, le plan, l'audit canonique et les preuves sont persistés. Les transitions
terminales et leurs preuves sont atomiques dans une même base SQLite ; les
lectures survivent à l'éviction et au redémarrage. Un verrou POSIX assure un
propriétaire d'exécution par base locale. Les jobs restés en cours sont marqués
interrompus ; seuls les jobs en attente sont repris par appel explicite avec
revalidation du mandat. Le backend par défaut utilise désormais les workers
Linux isolés avec réseau limité à la mission, quotas et nettoyage des helpers
et descendants. Le mode local historique demande une option administrateur
explicite. Voir le
[suivi P1](../product/EXECUTION_P1.md).
`.argos/` et `outputs/` contiennent des données runtime ignorées par Git.

La [roadmap de référence](../product/ROADMAP.md) porte les lots et leurs gates ;
le [noyau agentique](AGENTIC_CORE.md) détaille les sous-systèmes conçus.

## Worker sans réseau

`core/isolated_worker.py` fournit une primitive Linux séparée. Une unité
systemd utilisateur applique les quotas ; `worker_guardian.py` vérifie les
contrôles et lance bubblewrap avec namespaces privés, montages en lecture
seule, tmpfs bornés, environnement reconstruit et aucun accès réseau externe.
Un pipe de vie et le namespace PID permettent le nettoyage après la mort du
client, y compris pour un descendant détaché.

Cette primitive sans réseau n'est pas exposée à l'agent. Son dérivé
`NetworkWorker` est branché par défaut dans `ExecutionManager` : un namespace
ancêtre installe le pare-feu nftables avant le proxy slirp4netns ; l'outil
s'exécute sans les droits permettant de modifier ces règles. Profil, programme,
dépendances et règles sont associés à la demande et au reçu terminal. Les
contrôles de mission restent dans le runtime Argos. Voir les qualifications
[sans réseau](../product/WORKER_ISOLATION.md) et
[réseau de mission](../product/MISSION_NETWORK.md).
