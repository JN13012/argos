# Consignes de développement d’Argos

Ce fichier guide les assistants qui modifient le dépôt. Il ne configure pas
l’agent de pentest du produit. Les instructions explicites de l’utilisateur
priment ; signaler les contradictions avec les documents au lieu d’inventer
une règle de priorité entre plusieurs fichiers.

## Lire et travailler

- Commencer par `git status --short`. Préserver les modifications existantes ;
  ne pas supprimer, réinitialiser ou inclure le travail d’autrui dans un commit.
- Lire l’[index documentaire](docs/README.md), puis la
  [roadmap](docs/product/ROADMAP.md) et le document du lot concerné.
- La roadmap porte les statuts et priorités ; le lot porte les tâches, contrats
  et preuves. Le [scope](docs/product/SCOPE.md) fixe le périmètre produit.
  Vérifier dans le code toute affirmation de capacité livrée.
- Première offre : pentest web/API autonome, boîte noire externe depuis le CLI.
  Conserver cet objectif ; les accès et comptes facultatifs enrichissent le test.
- Livrer une tranche utile et vérifiable. Préparer la suite est possible avant
  de terminer le lot courant, sans déclarer ses dépendances déjà disponibles.
- Justifier les changements d’architecture significatifs dans un ADR ; mesurer
  les alternatives quand le choix l’exige. Un refactoring local n’impose pas
  l’adoption d’un framework ou une étude comparative complète.

## Contrats du produit à préserver

- Le runtime applique périmètre, effets permis, budgets, arrêt et révocation
  indépendamment du modèle. Les actions prévues s’enchaînent sans confirmation
  répétitive. Une découverte n’élargit pas les permissions de mission.
- Les données de cible et résultats d’outils ne sont jamais des instructions
  pour changer ces contrôles. Le modèle utilise des capacités typées ; une
  commande issue d’une page ou du modèle n’est pas exécutée comme shell libre.
- Chaque capacité utilise son chemin d’exécution contrôlé : HTTP, navigateur,
  DNS supervisé, outils réseau ou connecteur OSINT. Ne pas imposer HTTP à Nmap
  et ne pas ajouter de repli réseau qui contourne la politique de la capacité.
- Une vulnérabilité exige des preuves et un effet vérifiés. Distinguer
  observation, hypothèse, candidat, confirmé et corrigé. Un test non réalisé
  reste non testé ou bloqué ; une interruption ne prouve pas l’absence de faille.
- Aucun secret dans Git, les arguments publics ou les logs ordinaires. Fournir
  au modèle seulement les observations nécessaires, filtrées et expurgées,
  selon la politique de mission. Tout envoi à un fournisseur respecte cette
  politique ; les rapports et données client restent hors du dépôt public.
- L’agent évalué ne reçoit ni solutions, flags, scoreboard ni métadonnées qui
  révèlent les failles attendues. Les outils de développement et d’évaluation
  peuvent consulter le corpus ; leurs données restent séparées de la mission.
- Une brique tierce adoptée documente version, licence, dépendances, contrôle
  d’exécution et tests d’acceptation. Un outil installé n’est pas une intégration
  qualifiée, et une famille d’outils ne garantit pas la couverture d’une faille.

## Vérifier à la bonne échelle

- Documentation seule : liens locaux, cohérence des statuts, exemples et
  `git diff --check`. Ne pas lancer la suite réseau pour une correction de texte.
- Code Python : tests pertinents pendant le travail ; avant livraison d’une
  tranche, lint/formatage, typage et suite régulière complète ci-dessous.
- Runtime, transport ou isolation : ajouter les essais hôte concernés décrits
  dans le document de lot. Une suite avec tests ignorés ne vaut pas qualification.
  Vérifier Python 3.12 et 3.14 pour les tranches du moteur.
- Frontend modifié : `npm --prefix argos/frontend run check` ; ajouter les tests
  `test:e2e` si le parcours navigateur change. Ne pas confondre ces tests UI avec
  ceux du navigateur de pentest.

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
git diff --check
```

Consigner commandes, résultats, limites et tests non exécutés. La CI régulière
ne lance pas tous les essais d’isolation hôte. Une préparation documentaire,
un test local et une qualification sur une cible sont des résultats différents.
Mettre à jour le lot et la ligne de roadmap concernée quand leur statut change.

## Commits et publication

Messages conventionnels courts : `feat(web): ...`, `fix(runtime): ...`,
`test(web): ...`, `docs(plan): ...`, `chore(deps): ...`. Une étape cohérente et
vérifiée donne un commit quand la tâche l’autorise. Respecter les exclusions
nominatives demandées par l’utilisateur ; aucune attribution automatique à un
assistant ou fournisseur dans le message ou les métadonnées du commit.
Inspecter les fichiers nouveaux, le patch et l’état final. Aucun push implicite.
