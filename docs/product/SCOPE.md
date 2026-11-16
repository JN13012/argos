# Argos — Scope immédiat

Mise à jour : 16 novembre 2026. La [roadmap](ROADMAP.md) porte les statuts et le
[plan de pentest web](WEB_PENTEST_PLAN.md) organise la première offre commerciale.

## Priorité produit

Un pentest web/API autonome en boîte noire externe depuis le CLI : URL ou
domaine, découverte sans compte ni documentation, tests, validation, preuves,
rapport et recontrôle. Comptes et rôles supplémentaires sont facultatifs. L'agent doit
pouvoir enchaîner les actions préautorisées sans approbation répétitive. Le
niveau senior sera évalué ; il n'est pas une capacité actuelle du dépôt.

## Prochain travail : première chaîne web depuis le CLI

- [W1.1 livré](WEB_CONFIG.md) : configuration URL/domaine, périmètre, limites
  et comptes facultatifs, liée aux missions signées, sans connexion réseau.
- [W1.2 préparé](../../benchmarks/web/README.md) : sélection versionnée et
  contrôlée hors ligne ; cibles, oracles et images pas encore exécutés/qualifiés.
- [W1.3 spécifié](WEB_HTTP_EXECUTION.md) : transport, preuves, limites et premier
  test vérifié. La préparation W1 est terminée ; sa réalisation passe par W2/W3.
- [W2.1 livré](WEB_HTTP_POLICY.md) : contrats HTTP et configuration v2 signée,
  budgets et capacités, politique hors ligne et régressions v1. Aucun trafic.
- [W2.2 livré](WEB_HTTP_TRANSPORT.md) : résolution supervisée, worker HTTP
  épinglé à une IP, TLS vérifié et IPC privé ; essais sur endpoints locaux.
- [W2.3 livré](WEB_HTTP_RUNTIME.md) : runtime HTTP, tickets et compteurs
  persistants, preuves expurgées, audit et récupération sans renvoi implicite.
- [W3.1 livré](WEB_CLI_DISCOVERY.md) : CLI web, frontière persistante, liens et
  paramètres observés, sorties expurgées, arrêt et reprise explicite.
- **Prochain lot : W3.2**, redirection ouverte avec preuve, témoin corrigé
  et recontrôle ; aucune vulnérabilité confirmée par la découverte seule.
- Ajouter ensuite navigation anonyme et SPA, tests approfondis et boucle agent ;
  enrichir avec des comptes selon les accès disponibles.
- Évaluer les capacités démontrées sur les applications client, avec comparaison
  humaine et résultats reproduits. Les failles n'ont pas à être connues avant
  la mission ; leur nombre total inconnu interdit un score de rappel absolu.

W0/P1.5 poursuit la vérification du socle : refus, délais, révocation, panne,
reprise, quotas et nettoyage. Sa qualification Nmap réelle reste ouverte mais
ne bloque pas les travaux HTTP indépendants. Les contrôles nécessaires au web
sont vérifiés avant usage client. P0 et P1.1–P1.4 sont validés localement ; voir
le [bilan réseau](MISSION_NETWORK.md). Aucun pentest web autonome n'est encore
implémenté. Le [plan détaillé](WEB_PENTEST_PLAN.md) fixe les dépendances.

W1.1 livre les contrats Python et leur validation. Aucun nouvel outil actif,
endpoint métier, commande CLI web ou agent n'est ajouté.

## Travaux différés et fondations conservées

API/interface métier après validation du CLI ; délégation multi-agent après
une mission autonome mesurée. OSINT élargi, AD, cloud, DEFEND/GRC et sécurité
des LLM ne sont pas le chemin critique de cette première offre.

Le CLI SIRENE et les fondations d'exécution restent utilisables et testables
sans agent. La collecte conserve provenance et résultats partiels ; aucune
exhaustivité silencieuse n'est promise. Les capacités historiques ne sont pas
une preuve d'intégration fonctionnelle au futur parcours web.
