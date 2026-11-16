# W1 — Préparer le pentest web en boîte noire externe

Statut : **préparation W1 terminée** : W1.1 validé localement, W1.2 préparé
hors ligne et [W1.3 spécifié](WEB_HTTP_EXECUTION.md). Le transport, les cibles
et les mécanismes de notation restent à construire/qualifier.
Le [contrat effectivement accepté](WEB_CONFIG.md) utilise JSON UTF-8.
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

Exemple YAML de conception conservé pour lecture ; **le format implémenté
est JSON**, voir le [contrat et son exemple](WEB_CONFIG.md). Le YAML ci-dessous
n’est pas directement chargé par Argos :

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

- [x] Examiner et réutiliser les contrats existants dans `core/missions.py`,
  `core/scope.py`, `core/policy.py` et `core/approvals.py`.
- [x] Ajouter les modèles web dans un module dédié sous `backend/attack/web/`.
- [x] Implémenter chargement, validation et normalisation sans réseau.
- [x] Relier configuration et mission existante ; isoler les changements
  nécessaires aux missions Nmap et conserver leurs règles actuelles.
- [x] Tester URL seule, zéro compte, domaine nu, ports, IDNA, IPv6, exclusions,
  sous-domaines trompeurs, credentials intégrés et limites invalides.
- [x] Documenter le format effectivement accepté et les valeurs retenues.

Commit indicatif : `feat(web): add black-box mission config`.
Critère : configuration anonyme valide et refus déterministes prouvés ;
aucune connexion ni scan effectué par le chargement du fichier.

### W1.2 — Références de mesure

Préparation livrée dans le [corpus versionné](../../benchmarks/web/README.md),
avec manifeste JSON et contrôleur hors ligne :

- [x] Sélectionner 12 cas sur trois sources, épingler leurs commits et les
  empreintes de 28 fichiers de référence, dont les licences consultées.
- [x] Séparer métadonnées évaluateur et configuration minimale exportée à
  l'agent ; les mécanismes de notation restent à implémenter.
- [x] Prévoir 8 cas boîte noire sans compte ni description de faille, et
  4 CVE-Bench guidés évalués séparément.
- [x] Répartir 8 cas de développement et 4 réservés ; consigner contamination
  publique, aides amont et biais des défis à flag.
- [x] Définir 12 témoins corrigés et 6 cas de comportement avec états `planned`,
  sans prétendre que ces cibles sont construites ou vérifiées.
- [x] Distinguer guidé/boîte noire et contrôle des artefacts/résultat cyber ;
  aucun score de pentest n'est publié sans exécution.

Restent avant exécution : verrouillage des images et dépendances, ressources
mesurées, profil privé explicite, oracles isolés, témoins corrigés et cas de
comportement. Ces travaux accompagnent le transport et le runner ; W1.2 ne
qualifie pas leur exécution. Voir le corpus pour les points précis.

Commit indicatif : `test(web): define black-box evaluation cases`.
Critère de préparation : manifeste vérifié hors ligne et export sans indices
évaluateur ; images et résultats ne sont jamais inventés pour compléter ce lot.

### W1.3 — Passage à W2/W3

- [x] Fixer les interfaces requête, réponse, preuve, erreur et couverture.
- [x] Définir le contrôle DNS/origine/egress et ses essais de contournement.
- [x] Définir les budgets globaux, les réponses trop grandes, la concurrence,
  les backoffs, les erreurs TLS, la révocation et le stockage expurgé.
- [x] Choisir le premier test web reproductible avec témoin corrigé pour
  traverser CLI, exécution, validation, rapport et recontrôle.

Commit indicatif : `docs(web): specify HTTP execution slice`.
Spécification livrée dans [WEB_HTTP_EXECUTION.md](WEB_HTTP_EXECUTION.md).
La préparation W1 est close ; cela ne vaut pas qualification des images,
des témoins corrigés, du réseau, des oracles ou du CLI.

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

## Bilan W1.1

- Modèles immuables sous `backend/attack/web/`, chargeur JSON borné et
  normalisation hors ligne ; aucune dépendance ajoutée.
- Configuration liée à la mission, persistée atomiquement et incluse dans
  l'approbation signée ; aucune permission IP inventée à partir d'un domaine.
- Action HTTP déclarée mais exécution refusée jusqu'à W2 ; mission web
  inutilisable pour autoriser Nmap. Aucune commande CLI web ajoutée.
- **415 tests réussis sous Python 3.14 et Python 3.12**, dont 104 nouveaux tests
  web et 23 tests hôte activés explicitement. Ruff, formatage et Pyright propres.
- Suite complète exécutée avec `ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1` et
  les chemins explicites du proxy déjà qualifié ; aucun scan client effectué.
- Les points W2 (DNS/egress, plafonds d'exploration et de stockage cumulé) ne
  sont pas revendiqués par cette validation de configuration.

À la clôture de W1.1, la suite prévue était W1.2 puis W1.3 ; le bilan ci-dessous
consigne la préparation W1.2 désormais livrée.

## Bilan W1.2

- 12 cas référencés et contrôlés, 12 témoins corrigés et 6 comportements
  seulement prévus ; sources téléchargées dans `/tmp`, jamais exécutées.
- SHA-256 des 28 fichiers consultés vérifiés contre les checkouts ; aucun code
  ni contenu tiers n'est intégré au paquet Argos.
- Projection vers une configuration W1.1 anonyme, sans métadonnées évaluateur ;
  la projection ne remplace pas l'isolation des fichiers et du réseau.
- **122 tests web réussis sous Python 3.12 et 3.14**, dont 18 nouveaux tests
  d'intégrité, de séparation d'entrées et de détection d'altération.
- Suite normale sous Python 3.14 : **410 réussites, 23 tests hôte ignorés**.
  Les tests hôte ne sont pas rejoués pour cette préparation sans changement
  du runtime. Ruff, formatage et Pyright passent.
- Aucun conteneur construit, service démarré, scan client ou score de benchmark.

À la clôture de la préparation W1.2, W1.3 était le prochain lot ; sa livraison
est consignée ci-dessous.

## Bilan W1.3

- Contrats requête/réponse/erreur/preuve/couverture, chaîne DNS → IP épinglée
  → HTTP/TLS et entrée privée du worker spécifiés.
- Budgets, redirections, Retry-After, révocation, preuves expurgées et reprise
  définis ; les limites réelles de montage et de sortie du worker sont prises
  en compte, sans prétendre qu'elles isolent déjà un navigateur.
- Premier test choisi : redirection ouverte, avec deux marqueurs synthétiques
  sans connexion externe et un témoin corrigé à réaliser en W2/W3.
- W2.1–W3.2 découpés avec critères vérifiables. Prochaine implémentation :
  **W2.1 — contrats HTTP, configuration v2 et politique hors ligne**, désormais
  [livré](WEB_HTTP_POLICY.md). La prochaine implémentation est W2.2.
- Changement documentaire uniquement : liens locaux, fences Markdown et diff
  vérifiés ; aucun test d'exécution, scan, score ni nouvelle requête réseau
  du produit. La suite Python n'est pas rejouée pour cette spécification.
