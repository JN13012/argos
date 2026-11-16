# Argos — Architecture

État des sources au 16 novembre 2026. Monolithe modulaire, package Python unique,
frontend React/TypeScript/Vite séparé pour son outillage.

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
durable et le worker isolé restent à construire. Le choix d’un agent existant,
dont Hermes, ou d’un moteur propre passe par une évaluation. Aucune brique
adoptée ne peut contourner les permissions du runtime Argos.

Une mission peut autoriser à l’avance plusieurs étapes : l’autonomie ne dépend
pas d’une validation humaine de chaque appel. Les décisions hors mandat et les
conditions d’arrêt restent gérées indépendamment du modèle.

## Contrats et stockage

Les capacités métier restent appelables sans agent. L’orchestrateur adaptatif
dépend du protocole typé `ReconExecutionManager`, pas d’une implémentation de
test. Les imports `argos.osint.models` réexportent explicitement les classes
canoniques sans dupliquer leur logique.

`pyproject.toml` et `uv.lock` pilotent le Python ; le frontend conserve son
`package.json` et son lock npm. SQLite sert aux observations et aux registres
locaux. Les jobs en mémoire ne constituent pas encore une file durable.
`.argos/` et `outputs/` contiennent des données runtime ignorées par Git.

La [roadmap de référence](../product/ROADMAP.md) porte les lots et leurs gates ;
le [noyau agentique](AGENTIC_CORE.md) détaille les sous-systèmes conçus.
