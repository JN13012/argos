# M2.6 — Contextual Enumeration Engine

## Audit et tranche livrée

Base : main `4094171`. Aucune boucle LLM, aucun travail M2.7/M3. Le moteur
compose les capacités existantes et conserve un seul chemin d'exécution.

| Composant | Avant | M2.6 |
| --- | --- | --- |
| Wordlist Manager M2.2 | Inventaire local, normalisation, empreintes et sous-listes Quick/Standard/Deep | Même sélection bornée ; snapshot explicite, classement contextuel et comparaison avec l'ordre prédéfini |
| Gobuster / ffuf | Outils isolés, relais privé, un ticket HTTP par GET, précontrôles et échéances | Fonction `pipeline.enumerate_paths` partagée ; aucune modification du bootstrap ou des workers |
| Réseau M2.3 | Inventaire TCP lié aux reçus et profils signés | Relu indirectement par la carte M2.5 et le fingerprinting corrélé ; aucune nouvelle sonde ou mission IP déduite |
| Fingerprinting M2.4 | États, versions et preuves ; catalogue limité | Indices PHP/WordPress/JS non contradictoires, attachés à leur origine ; pas de nouveau catalogue |
| Cartographie M2.5 | Ressources et API observées/documentées, inconnues et contradictions | Promotion de références littérales non examinées, preuves et méthodes explicitement conservées |
| State / Evidence | Reçus HTTP/Nmap, cartes et snapshots `ReconStore` | Plans et bilans versionnés dans le même magasin ; couverture recalculable et récupération sans rejeu |

La préparation ne parcourt pas le réseau ni l'inventaire complet de corpus.
Elle réutilise les premiers sous-ensembles bornés du Wordlist Manager. Aucun
nouvel outil, dépendance, datastore ou moteur de reconnaissance parallèle.

## Planification explicable et CLI

```bash
python -m argos recon context-plan --db BASE_PRIVEE --map-run-id UUID_CARTE \
  --wordlist-profile quick --max-candidates 32 --request-budget 64
# Comparaison, avec les mêmes sources, plafond et listes :
python -m argos recon context-plan --db BASE_PRIVEE --map-run-id UUID_CARTE \
  --strategy predefined --wordlist-profile quick \
  --max-candidates 32 --request-budget 64
python -m argos recon context-plan-report --db BASE_PRIVEE --plan-id UUID_PLAN
python -m argos recon context-run --db BASE_PRIVEE --plan-id UUID_PLAN \
  --public-key CLE_PUBLIQUE --ca-bundle BUNDLE_CA_ADMINISTRATEUR
python -m argos recon context-report --db BASE_PRIVEE --run-id UUID_EXECUTION
# Après perte du processus, explicitement et sans trafic :
python -m argos recon context-recover --db BASE_PRIVEE --run-id UUID_EXECUTION
```

`--wordlist` / `--ffuf-wordlist` permettent des fichiers administrateur explicites ;
`--wordlist-home` conserve le corpus local existant pour Standard/Deep.
Le lanceur charge les helpers permanents ; `context-run` accepte aussi
`--slirp` / `--slirp-library`, avec les mêmes valeurs administrateur que le CLI
historique. Un mandat dont les plafonds dépassent l'enveloppe du profil est
refusé, conformément au contrat M2.2 ; aucun mandat n'est réécrit ou élargi.

Classement stable : GET documentés par la carte, autres références littérales,
correspondances de profil API/WordPress/JavaScript ou PHP, puis ordre prédéfini.
Chaque candidat conserve méthode, URL privée, seed, entrée, outil, priorité,
motifs, nœuds de carte et références de preuve. Une entrée de corpus générique
reste une hypothèse, avec provenance du fichier et empreinte du sous-ensemble ;
elle n'acquiert pas une preuve de présence. Les indices technologiques d'une
origine ne favorisent pas les listes d'une autre origine.

Déduplication par cible GET exacte, entre listes, outils et seeds qui se
recouvrent. Les sources supplémentaires restent attachées au candidat unique.
Aucune expansion de templates, de query, d'origine ou de répertoire de seed.
Les paramètres effacés de la carte ne sont pas reconstruits pour être fuzzés.
Formulaires, opérations uniquement non-GET, frontières d'authentification connues,
chemins hors scope et effets refusés par le Policy Engine restent exclus.
Une contradiction est conservée comme incertitude, jamais comme indice positif.

Les GET déjà terminés ne sont pas rejoués ; les requêtes incertaines restent
inconnues/interrompues. La déduplication courante est relue après acquisition du
verrou HTTP ; une observation arrivée depuis la création du plan est référencée
et réutilisée. Un plan consommé ne se réexécute pas : créer explicitement un
nouveau plan depuis les observations vérifiées. Aucun approfondissement automatique.

## Budgets, exécution et preuves

Plan : 2 048 candidats analysés, 512 sélectionnés au plus, historique borné à
8 192 transactions. Groupes par seed et outil, au plus 32/128/256 entrées selon
Quick/Standard/Deep, contrat littéral de 200 caractères et 32 Kio par groupe.
Quatre requêtes sont réservées par groupe pour les précontrôles possibles.
Le plafond effectif est le minimum du budget demandé et du reliquat signé ;
le runtime reste seul responsable de l'admission définitive et des preuves.

Les limites natives ne changent pas : thread unique, délai Gobuster 100 ms,
ffuf 10 requêtes/s au plus, `-maxtime 110`, worker 120 s, plafonds de ressources
et réponses hérités. Une liste admissible peut donc rester partiellement examinée
si une échéance ou un budget est atteint. Les budgets ne sont jamais renouvelés
par la création d'un plan ou d'un run.

Le relais contextuel accepte les seules entrées prévues, plus le précontrôle
racine/UUID de Gobuster. Toute autre requête, traversée, répétition de cible ou
dépassement est refusé avant remise au runtime HTTP. Les précontrôles racine
peuvent répéter un GET déjà connu : ils sont explicitement comptés comme contrôles,
séparément des doublons de candidats. Les tools n'accèdent qu'au relais privé ;
chaque GET cible garde scope, grant signé, DNS supervisé, IP épinglée et preuve
avant remise. Aucune session, exploitation ou recherche de vulnérabilité.

Le plan n'est pas un mandat (`grant_verified=false`) ; son exécution exige la
configuration approuvée courante. SIGINT/SIGTERM, révocation, durée, quotas et
perte du worker conservent leurs effets d'arrêt. La fermeture normale du runtime
est distinguée d'un arrêt opérateur. La récupération acquiert les deux verrous,
réconcilie les requêtes via `WebStore` et reconstruit la couverture depuis les
reçus associés au propriétaire du runtime, sans lancer de worker ni rejouer de GET.

## Interface structurée et sens de la couverture

`context-plan-v1` et `context-run-v1`, ruleset `argos-context-v1` : interfaces
Python `create_plan`, `plan_report`, `run_context`, `context_report` et
`recover_context`, également utilisées par le CLI. Elles préparent un contrat de
consultation pour M3 ; aucun moteur décisionnel M3 n'est développé.

Les rapports revalident la carte et toutes ses preuves, l'historique figé, la
configuration, le snapshot de listes et le plan recalculé. La couverture vérifie
les UUID, propriétaires, cibles, empreintes, réponses et remises aux outils.
Une projection ou une couverture modifiée puis réhachée est refusée. SHA-256
ne protège pas contre un administrateur réécrivant toute la base et ses sources.
Les anciens rapports restent consultables après révocation, sans droit réseau.

Le ledger conserve tous les candidats, avec :

- `examined` : réponse HTTP terminée vérifiée, ou reçu antérieur explicitement
  référencé. Même un 401/404/405 constitue une réponse examinée ; aucun support
  métier de méthode ou absence de vulnérabilité n'en découle.
- `not_examined` : non sélectionné, refusé avant départ ou non atteint par l'outil,
  avec motif (scope, budgets, méthodes, worker, arrêt, etc.).
- `unknown` : référence non actionnable/contradictoire ou issue incertaine.
- `interrupted` : transaction incertaine annulée/interrompue après départ possible.

Une absence de reçu n'est jamais un examen. Les bilans distinguent requêtes
réellement consommées, admissions conservatrices, contrôles, requêtes de candidats,
doublons, statuts HTTP et motifs d'arrêt. `response_observed` désigne une réponse,
pas un endpoint ou une vulnérabilité confirmé. Les 404, refus et redirections
restent séparés. Une réponse dont le hash correspond à un précontrôle UUID 2xx
devient `generic_response_suspected` ; les sorties positives d'un outil seules
ne prouvent jamais sa présence. Pas de détection universelle de soft 404 dynamiques.

## Qualification comparative

Les fixtures et leurs labels restent dans les tests. Le moteur reçoit seulement
les réponses déjà collectées, cartes vérifiées et listes explicites. Les trois
laboratoires HTTP loopback ont des structures connues ; le marqueur CMS est
synthétique et ne qualifie pas une installation réelle de WordPress.

Même entrée par stratégie : un GET initial archivé, trois candidats et un budget
maximal de 16 nouvelles requêtes. Chaque essai consomme effectivement cinq GET
(trois candidats et deux précontrôles) ; le GET initial identique est hors coût
d'énumération. Profils Quick comparés avec les vrais Gobuster/ffuf :

| Laboratoire | Pertinents prédéfinis | Pertinents contextuels | Ressources présentes retrouvées | Requêtes par stratégie | Faux positifs / doublons candidats |
| --- | --- | --- | --- | --- | --- |
| Portail | 1/3 | 3/3 | 1/3 → 3/3 | 5 | 0 / 0 |
| API | 0/3 | 2/3 | 0/2 → 2/2 | 5 | 0 / 0 |
| CMS synthétique | 0/3 | 3/3 | 0/3 → 3/3 | 5 | 0 / 0 |

Au total : pertinence 1/9 (11,1 %) → 8/9 (88,9 %), rappel des huit ressources
présentes 1/8 → 8/8, pour 15 requêtes par stratégie, dont six contrôles.
L'API documente aussi un chemin absent : sa réponse 404 reste négative.
Les faux positifs comparent les réponses 2xx non génériques au référentiel du
laboratoire ; ce score n'est pas une garantie de validité d'endpoints clients.

Cette comparaison isole **l'ordre des sélections depuis les mêmes observations**.
Ce n'est pas une comparaison des missions complètes avec `Exploration` : le
pipeline historique peut déjà suivre ces liens HTML/OpenAPI avant ses listes.
Le gain démontré est une priorité plus utile sous budget, pas une nouvelle
capacité de découverte inaccessible à M2.2. Les trois profils sont aussi comparés
sur fixtures synthétiques à budgets égaux ; leurs petits corpus sont identiques.
La qualification de grands corpus Standard/Deep n'est pas revendiquée.

Contre-épreuve générique : Gobuster s'arrête sur son précontrôle ; ffuf reçoit
deux réponses 200 identiques au contrôle, toutes deux gardées ambiguës. Bilan
partiel : deux examinés, six non examinés, quatre GET consommés, zéro doublon.
Aucune conclusion d'absence sur les six autres. Les tests couvrent aussi grant
révoqué, arrêt en requête, preuve conservée, récupération explicite, absence de
rejeu et falsification de plan/couverture.

## Validation et limites restantes

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -q -o faulthandler_timeout=30
export ARGOS_PROJECT_HOME="$PWD"
source "$HOME/.config/argos/environment.sh"
ARGOS_TEST_NETWORK=1 .venv/bin/python -m pytest -xq -s \
  tests/test_context_qualification.py tests/test_context_relay_host.py \
  tests/test_application_mapping_host.py tests/test_fingerprinting_host.py \
  tests/test_web_transport.py -o faulthandler_timeout=30
# Même sélection avec Python 3.12 ; contre-épreuve générique renforcée rejouée.
ARGOS_TEST_TOOL_REGISTRY="$ARGOS_TOOL_REGISTRY" ARGOS_TEST_NETWORK=1 \
  .venv/bin/python -m pytest -xq -rs tests/test_recon_network.py \
  -o faulthandler_timeout=30
# Même baseline historique sous Python 3.12.
git diff --check
```

Suite régulière finale : **1 177 réussis, 118 ignorés**, zéro échec, sous Python
3.14 (100,73 s) et 3.12 (102,80 s). Ruff, formatage et Pyright passent.
Qualification hôte distincte : **63 réussis, zéro ignoré** par version
(84,90 s sous 3.14, 82,72 s sous 3.12), plus contre-épreuve générique renforcée
3.12 : un réussi (6,33 s). Baseline historique : **14 réussis, deux ignorés** par
version ; les deux variantes sans registre nécessitent des paquets système absents
et ne sont pas qualifiées. Les variantes via registre administrateur et les trois
profils CLI restent vérifiés. Les ignorés réguliers ne valent pas qualification.
Les autres essais optionnels de confinement/navigateur n'ont pas tous été rejoués.

Baselines M2.4/M2.5 inchangées sur leurs essais hôte ; mêmes limites de signatures,
PHP contradictoire et FastAPI manqué. Manifestes privés M2.3/M2.4/M2.5 intacts.
Les anciennes fixtures, contrats et plafonds ne sont pas réécrits.

Limites : profils de pertinence volontairement étroits, bannières potentiellement
fausses, ordre déterministe sans modèle d'utilité appris, corps/query/templates
non fuzzés, aucune session ou authentification tentée, aucune poursuite automatique
après échéance. Les chemins inconnus hors des références/sous-listes restent non
examinés. Le fichier source peut disparaître après snapshot : l'exécution utilise
les seules entrées archivées, sans recharger un corpus différent.

Journaux, mesures, copie SQLite disponible et empreintes privés :
`.argos/qualifications/m26/`. Aucun scan externe, changement frontend,
assouplissement du confinement, exploitation, M2.7 ou M3. Publication sur main
uniquement après validation, conformément à la demande explicite de livraison.
