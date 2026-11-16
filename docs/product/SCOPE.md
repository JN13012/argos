# Argos — Scope immédiat

Mise à jour : 16 novembre 2026. La [roadmap](ROADMAP.md) porte les statuts et le
[plan de pentest web](WEB_PENTEST_PLAN.md) organise la première offre commerciale.

## Priorité produit

Un pentest web/API autonome depuis le CLI : authentification, plusieurs rôles,
cartographie, tests, validation, preuves, rapport et recontrôle. L'agent doit
pouvoir enchaîner les actions préautorisées sans approbation répétitive. Le
niveau senior sera évalué ; il n'est pas une capacité actuelle du dépôt.

## Prochain lot d'implémentation : W0 / P1.5

- Qualifier Nmap réel dans un laboratoire local autorisé, y compris ses fichiers
  de données et la reconnaissance en deux phases.
- Comparer aux services attendus ; vérifier refus, délais, annulation,
  révocation, crash, reprise, quotas et nettoyage.
- Documenter une installation reproductible des dépendances réseau et les
  environnements effectivement qualifiés.
- Réaliser la revue ciblée des frontières d'exécution et publier les limites.

P0 et P1.1–P1.4 ont été validés localement. Le worker réseau existe ; sa
qualification synthétique ne démontre pas encore la compatibilité Nmap réelle.
Voir le [bilan réseau](MISSION_NETWORK.md) et le [découpage P1](EXECUTION_P1.md).

## Lot de préparation suivant : W1

Figer le contrat de mandat web, les comptes/rôles, les budgets et les effets
permis ; construire le laboratoire réinitialisable et la vérité terrain. Définir
les scénarios réservés et le protocole d'évaluation avant le développement de
l'agent. Le détail des dépendances et critères figure dans le plan W0–W9.

Ce lot de planification livre uniquement les documents et l'organisation.
Aucun nouvel outil, endpoint métier, commande web ou agent n'est ajouté.

## Travaux différés et fondations conservées

API/interface métier après validation du CLI ; délégation multi-agent après
une mission autonome mesurée. OSINT élargi, AD, cloud, DEFEND/GRC et sécurité
des LLM ne sont pas le chemin critique de cette première offre.

Le CLI SIRENE et les fondations d'exécution restent utilisables et testables
sans agent. La collecte conserve provenance et résultats partiels ; aucune
exhaustivité silencieuse n'est promise. Les capacités historiques ne sont pas
une preuve d'intégration fonctionnelle au futur parcours web.
