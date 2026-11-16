# Argos — Architecture

État des sources au 16 novembre 2026. Monolithe modulaire, package Python unique,
frontend React/TypeScript/Vite séparé pour son outillage.

Priorité de réalisation : [pentest web autonome depuis le CLI](../product/WEB_PENTEST_PLAN.md).
Les adaptateurs HTTP et navigateur, le contrôle d'origine web, les sessions
multi-rôles et les services de mission sont une cible à construire. Le contrôle
IP/port livré ne suffit pas à isoler des origines web partageant une IP.

## Architecture actuelle

```text
argos/
├── __main__.py, cli.py       CLI OSINT et rapports
├── backend/
│   ├── api/                 FastAPI : santé HTTP et erreurs stables
│   ├── core/                Missions, scope, signatures, politiques et audit
│   ├── intel/osint/         Modèles, SIRENE, découverte, SQLite et rapports
│   └── attack/pentest/      Plans, Nmap, jobs supervisés, preuves, orchestration
├── osint/                   Réexportations de compatibilité des modèles
└── frontend/                Accueil minimal connecté à la santé de l’API
```

ATTACK P1 est une bibliothèque locale avec vérification des missions signées,
reconnaissance en deux phases et preuves vérifiées. Aucun endpoint métier ni
agent n’appelle encore ce moteur. Les runners synchrones historiques ne sont
pas le point d’entrée à exposer au futur harness. Les
[limites d’exécution](../product/PENTEST_P135_HARDENING.md) restent ouvertes.

La page montée est `frontend/src/app/App.tsx`. Les anciens composants de dossier,
chat local et scène 3D sont conservés comme travaux historiques, sans être
montés par cette page. Une réponse positive de santé ne valide aucune mission.

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
en bibliothèque et qualifié localement ; Nmap réel reste à qualifier. Le choix
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
