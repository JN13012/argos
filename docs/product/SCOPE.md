# Argos — Scope immédiat

Mise à jour : 16 novembre 2026. La [roadmap](ROADMAP.md) est la référence pour
les statuts et les dépendances entre lots.

## Lot courant : P0 — fiabilisation

- Corriger les diagnostics Python et conserver l’analyse de tout le workspace.
- Réparer l’installation locale et verrouiller les contrôles reproductibles.
- Contrôler lint, formatage et typage sur tout le Python, les tests backend,
  le frontend et ses parcours navigateur.
- Étendre la CI aux PR, à `main` et aux branches `feat/**`.
- Réconcilier vision, architecture et plans avec l’état réel des sources.
- Préparer l’évaluation des briques publiques ; aucun import de framework
  agentique, catalogue tiers ou nouvel outil actif dans P0.

Le [bilan P0](FIABILISATION_P0.md) consigne les commandes exécutées et les limites
de validation. La cible produit est une mission autonome, pas uniquement une
interface de conseil.

## Lot suivant : P1 — fiabiliser l’exécution

Capacité du gestionnaire, persistance des états, reprise après panne, quotas
système, contrôle du worker et qualification en labo. P0 ne livre ni ces
contrôles ni une API de scan. Les modifications du moteur correspondantes
restent un lot distinct.

## Fondations conservées

La découverte SIRENE persiste les entités avant de les enrichir ou de les
classer. L’analyse ne doit pas filtrer silencieusement la collecte ; aucune
exhaustivité territoriale n’est promise. Le scénario de découverte d’entreprises
reste utilisable et testable sans agent.

Les pages métier, les outils supplémentaires, les agents, le déploiement de
production et DEFEND/GRC ne sont pas implémentés dans P0.
