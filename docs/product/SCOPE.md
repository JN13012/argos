# Argos — Périmètre de la première offre web

Ce document fixe le périmètre produit, pas son avancement. Consulter la
[roadmap](ROADMAP.md) pour les capacités livrées et la prochaine tâche, le
[plan web](WEB_PENTEST_PLAN.md) pour la trajectoire et le
[catalogue](WEB_CAPABILITIES.md) pour les familles de tests à construire.

## Usage principal

Une application réelle de client, examinée depuis l’extérieur à partir d’une
URL ou d’un domaine. Le démarrage est boîte noire : sans code source, compte,
documentation interne ni liste de vulnérabilités attendues. Des comptes fournis
ou accessibles par les parcours permis et la documentation découverte peuvent
ensuite enrichir la mission. Leur absence n’empêche pas le démarrage ; elle
limite certains tests et doit apparaître dans la couverture.

La cible produit est une conduite autonome complète : découverte, hypothèses,
choix des capacités, exécution, vérification, adaptation, rapport et recontrôle.
L’opérateur configure les cibles, effets permis, limites et conditions d’arrêt
une fois ; les actions comprises dans ce cadre s’enchaînent sans validation
répétitive. Un mode assisté peut compléter ce parcours.

## Contenu attendu de l’offre initiale après qualification

- Applications HTTP(S), interfaces JavaScript et API REST/JSON. Découverte des
  routes, paramètres, technologies, API et parcours ; OpenAPI si disponible.
- Configuration/exposition, navigation, authentification et sessions,
  contrôle d’accès, entrées/injections, fichiers et logique métier selon leurs
  préconditions. Les identités disponibles déterminent les comparaisons
  possibles, sans deux comptes obligatoires au départ.
- Constats reproduits, impact contextualisé, preuves minimisées et expurgées,
  corrections proposées et recontrôle après correction.
- Rapports technique et décisionnel ; couverture, refus, parties non testées,
  hypothèses restantes, coûts et motifs d’arrêt explicités.
- Exécution depuis le CLI d’abord ; installation et exploitation chez un
  opérateur, sans imposer Docker ou un agent sur l’application du client.

« Complet » signifie une mission conduite jusqu’à sa restitution et une
couverture justifiée sur le périmètre annoncé. Cela ne garantit pas toutes
les vulnérabilités possibles. Le niveau senior est évalué sur les résultats,
le raisonnement métier, les omissions, les preuves et la qualité du livrable.

## Limites et approfondissements

GraphQL, WebSocket, SSO/MFA, conditions de concurrence, caches partagés et
ambiguïtés HTTP sont des approfondissements planifiés dans le catalogue.
Leur couverture exige des adaptateurs et essais spécifiques avant annonce.
Un obstacle d’authentification ou une précondition manquante reste un blocage,
jamais un résultat « non vulnérable » ou une conformité ASVS générale.

Déni de service, destruction de données et campagnes de mots de passe sont
hors du profil commercial initial. Les écritures de test utilisent des objets
identifiables, un journal et un nettoyage vérifié ; un résultat incertain
après crash est traité explicitement, sans répétition automatique.

Infrastructure/AD, cloud, OSINT généraliste, DEFEND/GRC et sécurité des LLM
suivent la première offre web. Le CLI SIRENE et les fondations Nmap restent
conservés. La délégation multi-agent et l’interface métier ne sont pas des
prérequis à la première mission autonome depuis le CLI.
