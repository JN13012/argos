# W1 — Préparer le pentest web en boîte noire externe

Statut : **prêt à implémenter**, aucune tâche ci-dessous n'est encore livrée.
Décision du 16 novembre 2026 ; dépend du [plan web](WEB_PENTEST_PLAN.md).

## Objectif et premier parcours

Partir d'une URL ou d'un domaine public de client, sans compte, sans code,
sans documentation et sans connaissance des vulnérabilités. La configuration
fixe les cibles et limites ; les détails techniques viennent de l'exploration.
Les comptes fournis sont optionnels et ne conditionnent jamais le démarrage.

Premier parcours livré progressivement par W1–W3 :

```text
URL/domaine → configuration validée → requêtes HTTP contrôlées
           → découverte de routes et paramètres → hypothèses applicables
           → premier test vérifié → preuve → rapport → recontrôle
```

W1 livre les contrats et leur validation ; W2 l'exécution HTTP ; W3 leur usage
depuis le CLI avec persistance. Ce premier parcours n'est pas encore un pentest
complet. W4 ajoute le navigateur, W5/W6 les tests approfondis et leur restitution,
puis W7 la décision autonome. Les tâches doivent rester utiles à la situation
client réelle, y compris en présence de redirections et d'une couverture partielle.

## Contrat de configuration à implémenter

Exemple de format **proposé**, pas un fichier déjà pris en charge :

```yaml
schema_version: 1
name: client-web
mode: external_blackbox
seeds:
  - https://app.example.com/
scope:
  origins:
    - https://app.example.com
  subdomain_roots: []
  excluded_paths: []
access:
  credential_refs: []
effects:
  allow_registration: false
  allow_test_writes: false
limits:
  duration_seconds: 1800
  max_requests: 5000
  requests_per_second: 2
  concurrency: 2
  request_timeout_seconds: 15
  response_bytes: 2097152
```

Ces valeurs sont un profil initial proposé, non des limites universellement
adaptées à tous les clients. Les limites du runtime existant restent applicables ;
la contrainte la plus restrictive prévaut. Le coût du modèle et du navigateur
sera ajouté avant W7/W4. Les plafonds de retries, profondeur, URLs uniques et
stockage cumulé doivent être fixés et testés en W2/W3 ; le plafond de requêtes
seul ne borne pas la mémoire, le disque ni le coût d'inférence.

Règles de validation et de normalisation :

- `mode` vaut `external_blackbox` par défaut. Aucun secret, compte, type de
  faille, technologie, fichier OpenAPI ou nom de CVE n'est requis.
- Une URL de départ est une graine de découverte, pas une permission implicite
  sur toute son infrastructure. Une URL HTTPS n'inclut pas automatiquement HTTP.
- Un domaine nu est normalisé en graine HTTPS ; la découverte HTTP nécessite
  une origine HTTP incluse explicitement dans la configuration. Cette règle
  doit apparaître dans le plan affiché, sans rétrogradation silencieuse.
- Une origine est le triplet schéma/hôte/port canonique. Rejeter les URLs avec
  identifiants intégrés et traiter IDNA, ports, IPv6 et fragments explicitement.
- Les sous-domaines ne sont inclus que par une racine explicite ; comparaison
  par labels DNS, sans suffixe approximatif. Les exclusions priment toujours.
- Les liens vers d'autres actifs sont enregistrés comme candidats ; aucun
  appel actif hors périmètre. Un sous-domaine inclus reste soumis aux autres
  contrôles, notamment IP résolue et exclusions.
- Le contrôle des chemins doit spécifier encodage et normalisation, sans
  supposer que tous les serveurs interprètent les ambiguïtés de la même façon.
  Les cas ambigus ne permettent pas de contourner une exclusion.
- Les adresses privées, loopback et link-local sont exclues du profil externe ;
  les benchmarks privés utilisent un profil de déploiement séparé explicite,
  sans désactiver le contrôle d'origine et sans règles cachées selon le nom du site.
- Les références de secrets sont facultatives ; les valeurs ne sont ni dans
  la configuration publiée, ni dans les erreurs, logs et rapports ordinaires.
- Pas de création de compte ni d'écriture métier par défaut. Quand ces capacités
  sont activées initialement, Argos les enchaîne sans confirmation par action ;
  les formulaires sont classés selon leurs effets, pas seulement leur méthode HTTP.
- Requêtes invalides, limites nulles/négatives, ambiguïtés et versions inconnues
  sont refusées avant toute connexion. La configuration n'est pas une seconde
  source de permissions : sa projection dans mission/signature/politique
  existantes est vérifiée ; aucun chemin web parallèle ne contourne ces contrôles.

## État de découverte à définir

| Objet | Informations minimales |
| --- | --- |
| Actif | Origine, source de découverte, inclus/exclu/candidat, raison et date |
| Route | URL canonique, méthode, paramètres connus, origine de la preuve, statut HTTP, identité utilisée |
| Surface | Formulaire, appel API, ressource JavaScript ou parcours ; liens vers observations |
| Hypothèse | Propriété suspectée, prérequis, capacité disponible, priorité et budget |
| Couverture | Test applicable, prévu/exécuté/vérifié/bloqué/non testé/non applicable et justification |
| Constat | Candidat/confirmé/rejeté/corrigé ; reproduction, effet observé et preuves |

Conserver les différences entre utilisateurs et les valeurs de paramètres sans
fusionner abusivement des routes distinctes. Dédupliquer et borner la frontière
d'exploration pour ne pas boucler sur calendriers, pagination et URLs aléatoires.
Une documentation absente ou un compte absent ne prouvent pas l'absence de route.
Définir les contrats sans créer un second système de stockage de preuves.

## Tâches et commits prévus

### W1.1 — Configuration et périmètre

- [ ] Examiner et réutiliser les contrats existants dans `core/missions.py`,
  `core/scope.py`, `core/policy.py` et `core/approvals.py`.
- [ ] Ajouter les modèles web dans un module dédié sous `backend/attack/web/`.
- [ ] Implémenter chargement, validation et normalisation sans réseau.
- [ ] Relier configuration et mission existante ; isoler les changements
  nécessaires aux missions Nmap et conserver leurs règles actuelles.
- [ ] Tester URL seule, zéro compte, domaine nu, ports, IDNA, IPv6, exclusions,
  sous-domaines trompeurs, credentials intégrés et limites invalides.
- [ ] Documenter le format effectivement accepté et les valeurs retenues.

Commit indicatif : `feat(web): add black-box mission config`.
Critère : configuration anonyme valide et refus déterministes prouvés ;
aucune connexion ni scan effectué par le chargement du fichier.

### W1.2 — Références de mesure

- [ ] Sélectionner un sous-ensemble de benchmarks existants et épingler les
  versions/images ainsi que leurs conditions d'usage.
- [ ] Enregistrer séparément URL fournie à Argos, prérequis techniques,
  ressources, résultat attendu et mécanisme de vérification externe.
- [ ] Attribuer le profil boîte noire à au moins deux tiers des missions :
  aucune CVE, catégorie de faille, solution ou documentation interne donnée
  à l'agent. Les pistes visibles publiquement dans la cible restent accessibles.
- [ ] Séparer jeux de développement et jeux réservés ; identifier contamination
  connue, aides imposées par les suites et biais des défis à flag.
- [ ] Inclure les cas sans faille attendue, chemins inaccessibles, soft-404,
  SPA, changement d'origine et session absente. Ajouter des témoins corrigés
  lorsque le benchmark ne les fournit pas.
- [ ] Noter les scores guidés séparément ; ne pas confondre un seul objectif
  réussi avec la couverture entière de l'application.

Commit indicatif : `test(web): define black-box evaluation cases`.
Critère : manifeste des cas exploitable par le futur runner, résultats attendus
séparés du contexte agent ; aucun score de réussite inventé avant exécution.

### W1.3 — Passage à W2/W3

- [ ] Fixer les interfaces requête, réponse, preuve, erreur et couverture.
- [ ] Définir le contrôle DNS/origine/egress et ses essais de contournement.
- [ ] Définir les budgets globaux, les réponses trop grandes, la concurrence,
  les backoffs, les erreurs TLS, la révocation et le stockage expurgé.
- [ ] Choisir le premier test web reproductible avec témoin corrigé pour
  traverser CLI, exécution, validation, rapport et recontrôle.

Commit indicatif : `docs(web): specify HTTP execution slice`.
W1 peut être clos lorsque ses tâches sont réalisées et leurs résultats publiés.
Les interfaces ne valent pas implémentation de l'egress ou du CLI.

## Acceptation du premier incrément exécutable W2/W3

Une seule URL suffit. Sans connaissance interne, Argos découvre plusieurs
routes et paramètres, distingue une fausse route, produit des observations
sourcées et exécute le premier test retenu avec un résultat vérifiable.
Une redirection vers une origine exclue ne déclenche aucune connexion vers elle.
Un login inaccessible donne une limite de couverture explicite, sans échec
artificiel de toute la mission et sans conclusion de sécurité sur la partie privée.
Le rapport rend les constats et les limites, et la mission peut être arrêtée et
reprise avec les contrôles existants. Le témoin corrigé invalide le constat.

Validation adaptée au code livré : tests ciblés des nouveaux contrats puis
régressions des politiques/CLI touchés, Ruff, formatage, Pyright et diff propre.
Les essais réels ne commencent qu'avec le transport W2 effectif. Aucun ajout
de navigateur, framework d'agent ou scanner supplémentaire dans W1.1.
