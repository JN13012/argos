# Argos — Scope immédiat

Mise à jour : 16 novembre 2026. La [roadmap](ROADMAP.md) porte les statuts et le
[plan de pentest web](WEB_PENTEST_PLAN.md) organise la première offre commerciale.

## Priorité produit

Un pentest web/API autonome depuis le CLI : authentification, plusieurs rôles,
cartographie, tests, validation, preuves, rapport et recontrôle. L'agent doit
pouvoir enchaîner les actions préautorisées sans approbation répétitive. Le
niveau senior sera évalué ; il n'est pas une capacité actuelle du dépôt.

## Prochain travail : première chaîne web depuis le CLI

- Définir la configuration de mission : URLs, comptes, débit, durée et actions.
- Sélectionner des benchmarks existants pour mesurer les résultats ; éviter de
  reconstruire une collection de cibles déjà disponible.
- Construire W2/W3 : exécution HTTP contrôlée, cartographie, preuves et rapport.
- Ajouter ensuite navigateur, comptes multiples, tests et boucle agent.
- Évaluer les capacités démontrées sur les applications client, avec comparaison
  humaine et résultats reproduits. Les failles n'ont pas à être connues avant
  la mission ; leur nombre total inconnu interdit un score de rappel absolu.

W0/P1.5 poursuit la vérification du socle : refus, délais, révocation, panne,
reprise, quotas et nettoyage. Sa qualification Nmap réelle reste ouverte mais
ne bloque pas les travaux HTTP indépendants. Les contrôles nécessaires au web
sont vérifiés avant usage client. P0 et P1.1–P1.4 sont validés localement ; voir
le [bilan réseau](MISSION_NETWORK.md). Aucun pentest web autonome n'est encore
implémenté. Le [plan détaillé](WEB_PENTEST_PLAN.md) fixe les dépendances.

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
