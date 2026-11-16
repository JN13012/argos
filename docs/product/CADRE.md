# Argos — Cadre du projet

## Projet

Argos est un projet de fin d'études Epitech, en quatrième année, spécialité
cybersécurité, encadré et évalué par l'équipe pédagogique d'Epitech Marseille.
Sa finalité est pédagogique et démonstrative, avec périmètre explicite et
traçabilité des observations.

Une première offre commerciale de pentest web autonome est désormais visée.
Cette orientation ne vaut ni disponibilité commerciale actuelle ni qualification
professionnelle : le [plan web](WEB_PENTEST_PLAN.md) exige une évaluation,
une revue experte et des pilotes explicitement autorisés avant généralisation.

## OSINT

- Utiliser des sources publiques ou légalement accessibles ; privilégier les
  API officielles et l'open data.
- Respecter les conditions applicables, les limites de débit et les règles
  d'accès des sources, notamment `robots.txt` pour les sites concernés.
- Ne contourner ni authentification, ni CAPTCHA, ni paywall, ni autre protection
  technique pour collecter des données.
- Prioriser les organisations et établissements ; minimiser les données
  personnelles et définir leur finalité et leur durée de conservation avant
  toute collecte. Aucun profilage de particuliers n'est prévu.
- N'automatiser aucune prise de contact dans le scope actuel.

Les conditions de collecte et de stockage devront être vérifiées avant
l'intégration de chaque source, conformément aux [principes OSINT](OSINT.md).

## Missions actives et autonomie

Les actions offensives actives nécessitent un périmètre explicitement autorisé :
laboratoires de l'équipe, plateformes d'entraînement selon leurs règles ou cible
avec autorisation écrite. La découverte d'un actif n'autorise pas son test.

Le moteur ATTACK P1 existe en bibliothèque ; il n'est pas exposé comme service
de scan. Sa présence ne vaut pas qualification de production.

La cible est une conduite autonome des missions : l'autorisation initiale peut
préapprouver les familles d'actions nécessaires, dans des limites explicites.
Une nouvelle cible, une permission supplémentaire ou une action non couverte
ne peut pas être autorisée par le modèle lui-même. La révocation et les
conditions d'arrêt restent applicables pendant l'exécution.

Ce cadre définit l'usage prévu du projet ; il ne vaut pas autorisation de tester
une cible réelle. Les statuts d'implémentation sont suivis dans la
[roadmap](ROADMAP.md).
