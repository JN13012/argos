# M2.5 — Application Mapping Engine

## Consolidation et audit

M2.4 consolidé depuis `6298e8d`, intégré par fast-forward et publié sur main
au commit `199ba35`. [CI vérifiée sur ce SHA](https://github.com/JN13012/argos/actions/runs/45507082731) :
Python 3.12, Python 3.14 et frontend/navigateur verts. Six rapports archivés
revalidés ; quatre occurrences de technologies contradictoires gardent confiance
nulle et aucune version sélectionnée. Le [catalogue limité M2.4](FINGERPRINTING.md)
est conservé, avec ses faux positifs et manques documentés.

| Composant existant | Réutilisation / changement M2.5 |
| --- | --- |
| Nmap / M2.3 | `network_report`, jobs et preuves vérifiés ; hôtes, ports, protocoles et services, sans nouvelle sonde |
| Découverte Web | Captures `Frontier` et références HTML/JS/OpenAPI historiques relues ; aucun enrichissement rétroactif inventé |
| Runtime HTTP | Ajout d'indices applicatifs minimisés au reçu atomique existant, pendant les requêtes déjà autorisées |
| Navigateur | `NavigationStore` / `NavigationEvidence` : liens DOM et XHR/fetch archivés, sans relancer Chromium |
| Fingerprinting | Même corrélateur, signatures et états ; aucun deuxième catalogue |
| State / Evidence | `WebStore`, `EvidenceStore`, `JobStore` et `ReconStore` ; projection versionnée dans `recon_runs`, aucun second magasin d'actifs |

Auparavant, les formulaires étaient comptés sans détails archivés ; les
références OpenAPI ne préservaient pas toutes les méthodes et paramètres.
Les anciennes archives ne permettent donc pas de reconstruire ces données.
Aucune dépendance ajoutée ni modification de Policy Engine, workers ou frontend.
Le découpage reste une projection locale de la reconnaissance existante.

## Contrat et consultation

```bash
python -m argos recon map --db BASE_PRIVEE --mission-id UUID_WEB
python -m argos recon map --db BASE_PRIVEE --mission-id UUID_WEB \
  --network-run-id UUID_RESEAU
python -m argos recon map-document --db BASE_PRIVEE --mission-id UUID_WEB \
  --base-url https://application.autorisee/openapi.json --file specification.json
# Réutiliser l'UUID renvoyé par map-document :
python -m argos recon map --db BASE_PRIVEE --mission-id UUID_WEB \
  --document-id UUID_DOCUMENT
python -m argos recon map-report --db BASE_PRIVEE --run-id UUID_CARTE
python -m argos recon map-query --db BASE_PRIVEE --run-id UUID_CARTE \
  --kind api_interface --state inferred
python -m argos recon map-query --db BASE_PRIVEE --run-id UUID_CARTE \
  --node-id IDENTIFIANT_NOEUD
```

L'API Python `map_application`, `application_report`, `query_application` est
le même chemin que le CLI. `application-map-v1` expose `nodes`, `relations`,
`sources`, `metrics`, `coverage` et `limitations`. Chaque nœud/relation a un ID
stable, un état, une confiance conventionnelle et les identifiants des sources.
Les attributs gardent leurs assertions et sources séparées dans `observations`.
La requête par ID renvoie son voisinage direct ; les filtres produisent un
sous-graphe induit sans relation pendante et les sources nécessaires seulement.

Types : `host`, `service`, `application`, `resource` (représentation page ou
ressource), `http_operation`, `api_interface`, `parameter`, `form`,
`authentication`, `technology`. Relations : exposition hôte/service, service /
application / ressource, résolution épinglée, endpoint réseau, références
HTML/JS/DOM, formulaire et action, paramètres, API documentées/appelées et
technologies associées.

- `observed`, confiance 0,8 : élément directement présent dans les preuves.
  Une requête terminée atteste son envoi et sa réponse, même 401/404/405 ;
  elle ne démontre pas le support métier de la méthode.
- `inferred`, 0,5 : existence suggérée par une référence, une définition OpenAPI
  ou une action de formulaire ; méthode annoncée distincte d'une méthode exercée.
- `unknown`, 0 : absence de renseignement éligible, notamment validation des
  sessions et accès ; jamais « authentification absente » ou « sécurisé ».
- `contradictory`, 0 : versions M2.4 incompatibles ou valeurs différentes pour
  des attributs exclusifs (action/méthode de formulaire, type, MIME, version).
  Les assertions restent présentes ; aucune résolution ni confirmation forcée.

Les états M2.4 `confirmed`/`probable` deviennent respectivement
`observed`/`inferred` dans la carte ; leur libellé initial et l'état de version
restent archivés. Les contradictions demeurent contradictoires. Les nombres de
confiance ne sont pas des probabilités calibrées ni des confirmations de faille.

Une application représente **une origine inférée**, pas une frontière métier
prouvée. Deux vhosts restent distincts. Un lien service web/réseau exige IP/port
épinglés identiques et conserve les deux preuves. Les paramètres se dédupliquent
par parent, emplacement et nom ; les valeurs de query, champs et corps ne sont
pas exportées. Les fragments et credentials sont supprimés/refusés. Les chemins
et noms peuvent être confidentiels : carte et reçus restent dans la base privée.

## Preuves et contrôles

`map-report` et toute requête structurée revalident les reçus HTTP, les captures,
les jobs Nmap, les navigations, les documents et la projection recalculée.
Une projection modifiée puis réhachée ou une preuve altérée est refusée. Les
sources incluent type, UUID, mission et SHA-256 ; les captures HTTP restent
liées à leur reçu et au profil/configuration. Les sélections HTTP/navigateur
sont figées : une nouvelle requête ne modifie pas une ancienne carte.
Une source réseau encore mutable peut invalider sa relecture après modification.
Les empreintes ne protègent pas contre un administrateur réécrivant toute la base.

`map-document` accepte seulement un JSON OpenAPI/Swagger fourni explicitement,
avec URL de base dans le scope existant. Le dépôt normalisé est lié à la mission,
à sa configuration et au SHA-256 du fichier initial. Le fichier brut n'est pas
archivé ni requis à la relecture. Cela trace une déclaration d'opérateur, sans
signer ni démontrer l'authenticité de l'auteur ou la conformité de l'application.
Les libellés attendus d'évaluation restent exclusivement dans les tests, hors des
entrées du moteur. Aucun accès au référentiel d'évaluation n'est ajouté.

Aucun DNS, socket, navigateur, outil, scan ou requête n'est lancé par l'analyse.
L'extraction des futurs reçus n'ajoute aucun trafic aux requêtes autorisées et
reste soumise à leurs budgets de preuve signés. Les mandats révoqués restent
consultables hors ligne ; aucune réactivation. Les références hors scope sont
marquées `out_of_scope` et n'accordent aucune permission ni insertion dans une
frontière d'exécution. Aucun effet, session ou exploitation M2.6 n'est préparé
comme une capacité déjà disponible.

## Bornes et limitations

- 256 reçus HTTP terminés, premiers dans l'ordre d'archive ; 64 jobs réseau au
  plus ; 10 navigations terminées/partielles liées aux reçus retenus, avec les
  bornes existantes de 64 ressources par navigation ; huit documents explicites.
- Corps/document : 262 144 octets ; 128 faits / 32 768 octets JSON de faits
  au plus par source ; 64 attributs par balise. Troncatures signalées.
  Noms de paramètres ASCII, 128 caractères au plus ; noms hors format omis,
  sans déduction d'absence de paramètres.
- Graphe : 4 096 nœuds, 8 192 relations, 32 768 assertions. Dépassement : refus
  explicite, sans enregistrer une nouvelle carte tronquée silencieusement.
- HTML statique seulement ; formulaires identifiés par URL et position. Leur
  réordonnancement peut produire une contradiction conservatrice. Pas de
  soumission, de validation de session, de SSO ou de contournement.
- JSON OpenAPI 3 / Swagger 2 : opérations, paramètres directs et propriétés
  directes des corps. Pas de YAML, résolution `$ref`, schéma récursif ni serveur
  multiple/override ambigu ; limites signalées. Les exigences de sécurité sont
  des déclarations génériques, pas une qualification des schémas OAuth/API keys.
- JavaScript : réutilisation des références statiques existantes ; pas de
  déduction de méthode depuis un simple appel textuel ni d'exécution. Les liens
  DOM archivés enrichissent la carte ; les liens jamais capturés restent inconnus.
- Les anciens reçus sans indices applicatifs ne fournissent ni formes détaillées
  ni méthodes OpenAPI effacées. Limitation explicite, aucun replay ; tableau vide
  signifie absence d'observation éligible, pas absence d'application ou d'API.
- Historique et réponses variant dans le temps peuvent paraître contradictoires ;
  pas d'arbitrage temporel, de fusion métier multi-origine ou de calcul de risque.

## Qualification mesurée

Trois fixtures synthétiques indépendantes : portail avec formulaire, API JSON
OpenAPI et SPA statique. Les réponses seules vont au runtime ; les attentes sont
conservées par l'évaluateur dans les tests. Résultats identiques sous 3.12/3.14 :

| Fixture | Ressources correctes / attendues | Opérations | Noms de paramètres | Formulaires | Relations témoins | Nœuds inconnus |
| --- | --- | --- | --- | --- | --- | --- |
| Portail | 4/4 | 3/3 | 2/2 | 1/1 | 2/2 | 2 |
| API | 3/3 | 4/4 | 3/3 | 0/0 | 2/2 | 5 |
| SPA | 4/5 | 2/2 | 0/0 | 0/0 | 3/3 | 1 |

Précision des ressources : 11/11 = 100 % ; complétude : 11/12 = 91,7 %.
La route SPA manquée n'existe qu'après état d'exécution absent des observations.
Zéro ressource ajoutée à tort, zéro doublon et zéro relation pendante.
Les sept relations témoins sont correctes ; ce n'est pas un score sémantique
exhaustif sur toutes les relations. Les 50 nœuds et 56 relations ont des sources
vérifiées, sans source orpheline. Aucun de ces chiffres ne garantit une
couverture universelle sur une application client.

Essai hôte : vrai serveur HTTP loopback, trois GET via mandats signés et workers
isolés ; formulaire, OpenAPI GET/POST déclaré et challenge Basic observés.
CLI `map`, `map-report`, `map-query` exercés ; **zéro requête d'analyse**, aucune
soumission POST. Services arrêtés, threads joints et deux mandats révoqués.
La baseline HTTPS/Nmap M2.4 est réexécutée sans changement : mêmes trois vraies
identifications, PHP contradictoire et FastAPI manqué, précision/rappel 75 %.
Six anciennes projections M2.4 revalidées et six cartes construites sur des
copies de leurs bases ; manifeste original inchangé.

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -q -o faulthandler_timeout=30
# Préparer comme le lanceur, avant de charger les chemins administrateur :
export ARGOS_PROJECT_HOME="$PWD"
source "$HOME/.config/argos/environment.sh"
ARGOS_TEST_NETWORK=1 .venv/bin/python -m pytest -xq -s \
  tests/test_application_mapping_host.py tests/test_fingerprinting_host.py \
  tests/test_web_transport.py -o faulthandler_timeout=30
# Même sélection hôte avec /tmp/argos-stabilization-py312/bin/python.
git diff --check
```

Suite régulière : **1 161 réussis, 112 ignorés**, zéro échec, sous 3.14
(108,08 s) et 3.12 (107,20 s). Qualification hôte distincte : **57 réussis,
zéro ignoré**, 31,90 / 31,82 s. Ruff, formatage et Pyright passent. Les ignorés
réguliers ne constituent pas une qualification ; les autres essais hôte n'ont
pas été tous réexécutés. Trois premiers lancements sans configuration complète
ont refusé l'isolation ou le registre local ; le chargement administrateur du
lanceur a permis la qualification, sans changement des contrôles.

Journaux, mesures, copies SQLite et empreintes privés :
`.argos/qualifications/m25/`. Aucun scan externe, changement frontend,
exploitation ou capacité M2.6. Décision : tranche validée avec les limites
ci-dessus ; publication et intégration main autorisées par la consigne finale
de l'utilisateur, après validation.
