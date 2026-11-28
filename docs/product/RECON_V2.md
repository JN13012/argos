# Recon V2

Base `32b418d38f881405a0fbaf2ed46e5e0a9711ff41`. La qualification M4
reprend les [essais M2.7](RECON_QUALIFICATION.md) et
[la consolidation M2.7.1](RECON_CONSOLIDATION.md).

## M4.1 — Corpus préparé

Le [catalogue](../../benchmarks/recon_v2/corpus.json) fixe six applications
et les empreintes des manifestes historiques. Pour Juice Shop 19, crAPI v1 et
DVWA, réutiliser la composition privée M2.7.1 et ses relais. Le catalogue
contient les digests des services, auxiliaires compris. La recette conservée
dans `.argos/qualifications/m271/compose.lock.json` reste privée. Avant une
campagne, contrôler la recette et les images locales, créer un projet et des
volumes distincts, vérifier réseau interne, écoute locale, état initial et
readiness. Le projet historique et ses volumes servent d'archives. La
qualification du reset et de l'isolation appartient à M4.2b. L'inspection
Docker locale a retrouvé les 11 images amd64 par digest pour les 13 services.

Les trois [applications WSGI](../../benchmarks/recon_v2/fixtures.py) sont
indépendantes et utilisent uniquement la bibliothèque standard. Le portail
couvre les liens relatifs et un refus d'identité. La SPA couvre un shell
générique, un appel JSON et un lien généré dans le DOM. Le catalogue REST
publie un contrat OpenAPI et un refus d'identité. Les refus sont simulés sans
comptes ni transactions. Chaque instance future doit servir un seul callable,
sur sa propre origine de test. Leur contrat HTTP peut être vérifié en mémoire
avant tout essai hôte.

Le référentiel est un fichier de l'évaluateur, distinct du code des fixtures et
des entrées de mission. Pour chaque chemin, l'installation, l'exposition, la
visibilité et l'authentification sont des dimensions indépendantes. Une règle
de proxy de préfixe ne confirme pas une route feuille. Les états `unknown`
restent hors des dénominateurs qui exigent une preuve. L'échantillon historique
de 33 chemins et ses témoins négatifs sont conservés. Une réponse HTTP,
y compris un 401 ou un shell 200, demeure une mesure différente de la
présence d'un endpoint.

Après les six applications initiales, viser trois applications locales
admissibles et trois applications réservées originales. Les variantes d'un
même build, les profils TLS et les pannes ne comptent pas comme des applications
supplémentaires. Les jeux de développement et de réserve sont séparés par
application. Les sessions authentifiées restent liées à W4.3c.

## M4.2a — Diagnostic hors ligne

Le [gel historique](../../benchmarks/recon_v2/baseline.json) fixe l'ensemble
des 17 chemins ayant une réponse et des 16 omissions des bras contextuels
M2.7 et M2.7.1. Le [lecteur](../../benchmarks/recon_v2/audit.py) contrôle
les manifestes (135 et 176 entrées). Il recalcule les rapports Network,
Context, Fingerprint et Application Map, relit les reçus et rapproche les
références, candidats, réponses et nœuds. Les diagnostics détaillés sont
privés. La lecture ne lance aucun navigateur, worker, modèle ou outil réseau.

```bash
umask 077
sortie=$(mktemp -d data/qualification/m42a.XXXXXX)
.venv/bin/python -B -m benchmarks.recon_v2.audit \
  --archives .argos/qualifications > "$sortie/report.json"
```

Le GET de `/api/Products` reste un cas historique de mesure. La source
archivée atteste un POST protégé. Elle ne permet pas de qualifier le GET.

Les 16 omissions relatives au référentiel exact ont zéro ticket sur les
chemins attendus. Elles se répartissent comme suit.

| Classe | Nombre | Preuve ou limite |
| --- | ---: | --- |
| Token JavaScript trop long | 2 | Les littéraux `/api/Products` et `/rest/products/search` sont présents dans le bundle principal Juice Shop. Le tokenizer les englobe dans un token de 23 478 caractères, au-delà de la limite de 8 192. Le rejeu ne produit aucune référence exacte. |
| Sélection | 2 | `/robots.txt` de Juice Shop et crAPI figure dans le plan avec `candidate_budget`. Les deux autres stratégies l'ont reçu en HTTP 200. |
| Référence serveur Juice Shop | 1 | Route de version attestée dans les sources historiques. Visibilité anonyme indéterminée. |
| Assets crAPI et DVWA | 4 | Présents dans les références historiques, sans candidat exact. La visibilité des deux assets crAPI et des deux assets DVWA doit être établie. |
| Préfixes du proxy crAPI | 3 | Le proxy atteste des préfixes. L'exposition des routes feuilles reste à vérifier. |
| Frontière de connexion DVWA | 4 | La collecte s'arrête sur la page de connexion. Le besoin d'identité de chaque ressource demeure indéterminé. |

Les rapports contextuels conservent les **54** états
`generic_response_suspected`, avec un reçu par URL. Les cartes finales
exposent les **54** ressources comme `observed`. L'état générique reste donc
disponible dans le ledger, mais le nœud seul ne restitue pas cette nuance. Le
rapport W6 et ses exports sont reconstruits sur chacun des six essais.
L'index W6 de la découverte contient 24, 4 et 3 reçus par campagne sur les
trois applications. **Aucun des 54 reçus d'énumération concernés n'est dans
cet index**. La conservation de l'incertitude dans une restitution qui
agrège découverte et énumération reste une porte ouverte.

| Composant M2.7.1 | Contribution sur les trois essais contextuels | Coût archivé |
| --- | --- | --- |
| Nmap | Trois couples IP/port observés ouverts | 14,58 / 24,53 / 14,48 s. Paquets non mesurés. |
| Collecte HTTP et extraction | 10 premières réponses de référence | 24 / 4 / 3 tickets. 23,42 / 10,60 / 2,84 s. |
| Cartes et fingerprinting | 17 relations de l'échantillon. Six des sept technologies du référentiel commun. | Carte initiale 0,06–0,24 s, fingerprinting 0,09–0,19 s, carte finale 0,24–0,67 s. |
| Gobuster | 73 candidats avec réponse, zéro première réponse du référentiel | 79 tickets avec ses contrôles. |
| ffuf | 23 candidats avec réponse, sept premières réponses du référentiel | 23 tickets sur ces essais. |
| Énumération totale | 96 candidats et six tickets de contrôle | 121,10 / 38,73 / 38,73 s. |
| DOM | Zéro navigation | Non mesuré. |
| API | Comptage des opérations projetées dans le graphe | Couverture API non mesurée. |

Le coût wall-clock par outil natif, le temps du tokenizer pendant la mission
et le trafic physique ne sont pas reconstructibles à partir des traces
actuelles. Le lecteur ajoute des chronomètres pour les projections hors
ligne. Ces valeurs incluent leurs propres vérifications et ne sont pas
additives. Les premières réponses sont attribuées selon l'ordre archivé.
Elles ne mesurent pas l'effet de retirer une étape.

## Portes M4.2b — À valider avant exécution

| Axe | Contrôle et seuil |
| --- | --- |
| Reproductibilité | Vérifier digests, montage, état initial, reset et fin propre. Trois répétitions appariées par cellule avec les mêmes binaires, stratégies et enveloppes signées. Séparer les phases de mise en place et d'exécution. |
| Réseau | Compter les couples IP/port soumis, observés et non résolus. Mesurer séparément durée et coût réseau si les compteurs d'hôte sont disponibles. Zéro sortie hors mandat. |
| HTTP | Préserver les 17 chemins historiques exacts et attribuer chaque écart à un stade, ou à une preuve manquante documentée. Distinguer réponse, accès, ressource référencée et endpoint confirmé. |
| DOM et API | Sur la SPA, suivre le document, le script, l'appel JSON et le lien DOM. Sur l'API, distinguer contrat OpenAPI et échange attesté par méthode et chemin. Aucun dénominateur commun avec les chemins HTTP. |
| Technologies | Préserver les 6/7 historiques à référentiel constant. Évaluer les versions attestées à part. Garder les déclarations et les contradictions. |
| Incertitude | Aucun témoin absent ni shell générique confirmé dans une vue de qualification. Contrôler ledger, carte et W6 selon leur portée. Les 54 divergences sont une dette connue et restent visibles tant que la projection n'est pas corrigée. |
| Intégrité et reprise | 100 % des renvois de preuve vérifiables. Refus, annulation, révocation, crash et nettoyage ont un résultat explicite. Zéro rejeu d'action incertaine. |
| Performance | Mesurer par étape avec les mêmes entrées, en ajoutant des horodatages autour des adaptateurs et de l'extraction dans le banc de qualification. Collecter tickets, répétitions, octets et CPU/RAM attribuables. Publier médiane et plage. P95 seulement à partir de 30 mesures comparables. |

Les tests hors ligne couvrent le contrat des fixtures, le refus d'archives
altérées et le diagnostic d'un token trop long. Les essais hôte réutiliseront
les fixtures existantes dans les tests de transport, navigateur et
reconnaissance, sous Python 3.12 et 3.14. Les résultats de suite ignorés
restent distincts de la qualification hôte. Les éventuelles corrections
du produit relèvent de M4.2c, après mesure à comportement constant.
Après une correction de l'extracteur, conserver ce diagnostic avec sa
révision de code et mesurer le nouveau comportement dans un rejeu distinct.

## Validation de cette tranche

Les trois fixtures ont fait l'objet de 15 vérifications de réponse en mémoire.
Les cinq tests ciblés `tests/test_recon_v2_audit.py` passent sous Python
3.12.15 et 3.14.6. Les six rapports de mission recalculés donnent les mêmes
projections avec les deux interpréteurs, hors chronométrage. Ruff, le contrôle
de formatage, Pyright sur le dépôt et le banc, les liens locaux et
`git diff --check` passent. Les contrôles Docker se limitent aux métadonnées
des images présentes.
La suite régulière `python -m pytest -q -o faulthandler_timeout=30` passe
sous les deux versions avec 1 457 réussites et 121 tests ignorés chacune
(140,79 s en 3.12 et 144,59 s en 3.14). Une première exécution sous sandbox
est interrompue après un blocage AnyIO. La relance hôte conserve les essais
optionnels réseau, navigateur et isolation désactivés. La qualification de
ces chemins, le reset des laboratoires et la mesure des durées propres aux
adaptateurs pendant une mission restent à faire en M4.2b.

## M4.2b — Qualification partielle

Base `0d8d0bb`. Le [banc](../../benchmarks/recon_v2/qualify_baseline.py)
vérifie l'empreinte SHA-256 du catalogue
`f4e73d282a321671a842fc175cf70cdc9281d5448443e3968a03f20c97d66a5f`.
Les dénominateurs restent 11 chemins historiques par application, et cinq
contrats HTTP par fixture. Un 401 ou un shell générique HTTP 200 représente
une réponse de référence. Le refus et la nature générique restent visibles
dans la notation. Le banc exécute des requêtes fixes sur ses propres serveurs
WSGI, bornés à la boucle locale. Son mode archives ne fait aucun trafic.

```bash
umask 077
sortie=$(mktemp -d data/qualification/m42b.XXXXXX)
.venv/bin/python -B -m benchmarks.recon_v2.qualify_baseline > "$sortie/fixtures.json"
.venv/bin/python -B -m benchmarks.recon_v2.qualify_baseline \
  --archives .argos/qualifications > "$sortie/archives.json"
```

| Environnement | HTTP | DOM et API | Réseau et cycle de vie |
| --- | --- | --- | --- |
| Juice Shop | 7/11 sur archives | DOM et API non mesurés | Archives et métadonnées Docker vérifiées. Campagne active non exécutée. |
| crAPI | 5/11 sur archives | DOM et API non mesurés | Archives et métadonnées Docker vérifiées. Campagne active non exécutée. |
| DVWA | 5/11 sur archives | DOM et API non mesurés | Archives et métadonnées Docker vérifiées. Campagne active non exécutée. |
| Portail WSGI | 5/5 par répétition | Défi d'authentification HTTP simulé, sans session | Boucle locale et fermeture du listener vérifiées sur trois répétitions par Python. |
| SPA WSGI | 5/5 par répétition. Le témoin absent retourne le même shell 200 que la racine. | Réponse JSON et route liées au contrat HTTP. Rendu contrôlé dans les essais Chromium séparés. | Même contrôle de cycle de vie que le portail. |
| API WSGI | 5/5 par répétition | GET `/v1/books` déclaré dans OpenAPI et observé par HTTP. Défi d'authentification du profil observé séparément. | Même contrôle de cycle de vie que le portail. |

Les trois fixtures sont sans état. Chaque répétition ouvre un listener neuf
et vérifie les statuts et empreintes de corps, identiques sur les trois essais.
Les neuf listeners ferment sous chaque Python. Cela vérifie la boucle locale
et le nettoyage du banc. Les essais d'isolation du worker couvrent séparément
la protection du fichier hôte, du réseau de l'hôte et la fin des descendants.
Le moteur d'inventaire TCP et la mesure du trafic physique restent non qualifiés.

Docker expose les 11 digests amd64 pour les 13 services historiques.
L'inspection du projet historique trouve 13 conteneurs arrêtés, zéro liaison de
port publiée par Docker et trois réseaux marqués internes. Les états initiaux,
la santé, le trafic, le reset et le nettoyage d'une nouvelle campagne dans les
trois piles historiques restent non mesurés.

### Coût des archives et portée de W6

| Application | Temps total M2.7 → M2.7.1 | Énumération | Tickets HTTP | CPU enfants | Pic RSS par processus enfant |
| --- | ---: | ---: | ---: | ---: | ---: |
| Juice Shop | 55,37 → 163,65 s | 7,15 → 121,10 s | 28 → 58 | 0,510 → 1,082 s | 70 484 → 70 536 Kio |
| crAPI | 25,95 → 79,36 s | 7,67 → 38,73 s | 11 → 38 | 0,171 → 0,556 s | 66 052 → 67 032 Kio |
| DVWA | 53,71 → 57,38 s | 35,74 → 38,73 s | 37 → 37 | 0,498 → 0,521 s | 57 852 → 56 956 Kio |

Au total, 76 → 133 tickets pour les mêmes 17 chemins du référentiel examinés.
Le temps passe de 135,03 à 300,39 s. L'énumération représente 147,98 s des
165,36 s supplémentaires. Juice Shop et crAPI passent d'une énumération
partielle à une exécution complète du plan. crAPI ajoute aussi 10,32 s
de réseau et 7,36 s de collecte. DVWA conserve le même nombre de tickets
et présente un écart de 2,98 s sur l'énumération. Ces différences localisent
le coût par phase. Les traces historiques ne permettent pas de l'attribuer
à un adaptateur, à une modification ou à la charge hôte de manière causale.
Le pic par processus enfant n'est pas la RAM cumulée de la mission.

Sur la qualification WSGI, la médiane de cinq requêtes par répétition est
comprise entre 6,75 et 8,96 ms selon la cellule Python/application. La plage
observée est 6,22–17,29 ms. Le CPU par répétition est de 8,13–22,25 ms, dont
démarrage et arrêt du serveur dans le même processus. Le pic RSS du processus
est de 30 708–37 088 Kio, cumulatif au cours du processus. Mesures
descriptives avec charge concurrente de validation. Ces observations
n'établissent aucun p95 et ne comparent pas les stratégies. Les appels HTTP
directs du banc n'émettent aucun ticket Argos. Les durées de préparation,
des échanges et de fermeture sont enregistrées séparément.

Le rapprochement est fait par identifiant de reçu. En M2.7.1, W6 indexe 31
reçus de découverte au total, soit 24, 4 et 3. Les 102 reçus
d'énumération sont en dehors de cet index. M2.7 présente 45 reçus
d'énumération hors index. Les 54 états génériques de M2.7.1 restent liés aux
preuves dans le rapport contextuel et apparaissent comme `observed` dans
la carte. La portée actuelle de W6 explique leur absence de l'index. Une vue
qui englobe l'énumération devra restituer la classification et sa provenance.

### Contrôles du worker Chromium et du runtime

Le test de worker existant exerce une fixture SPA distincte des callables
WSGI. Il vérifie, pour HTTP et TLS, trois reçus liés au document, au script
et à l'appel JSON, puis un lien DOM. Les trois répétitions par couple
Python/transport réussissent (12/12). Le temps du cas de test complet
inclut démarrage, capture, preuves et fermeture.

| Python | HTTP, médiane [min–max] | TLS, médiane [min–max] |
| --- | ---: | ---: |
| 3.12 | 11,02 [10,70–11,95] s | 11,56 [11,36–11,60] s |
| 3.14 | 11,31 [11,20–14,82] s | 11,65 [10,94–12,48] s |

Les essais séparés sur le worker
confirment le refus d'un certificat hors confiance, l'annulation pendant
un échange imbriqué et le nettoyage des processus après arrêt de leur
propriétaire. Les quatre contrôles hôte d'isolation, révocation et rollback
passent sous les deux Python. Les indicateurs de temps CPU et de pic mémoire
des groupes de tests se trouvent dans les fichiers `*.cost`. Leurs valeurs
agrègent pytest et ses enfants et ne sont pas des mesures par composant.

### Anomalies confirmées et recommandations M4.2c

- **CLI SPA**. Les trois essais CLI échouent sur les deux versions de
  Python avant le lancement du navigateur. La collecte initiale termine
  `partial/coverage_partial` et le CLI renvoie 3. Sur les bases de test
  conservées, le script est visité et la réponse API JSON est classée
  `non_html` sur HTTP et TLS. Le cas de réponse retenue expire pendant
  cette collecte statique. Les trois cas enregistrent quatre tickets et
  zéro navigation. Il faut trancher le contrat entre collecte partielle,
  preuve API non HTML et passage explicite au navigateur. Préserver le
  résultat partiel, les refus et la reprise sans rejeu dans les tests.
- **Incertitude de présence**. Conserver la preuve de transport des 54
  réponses génériques tout en faisant apparaître leur ambiguïté dans la
  carte. L'index W6 garde un périmètre explicite. Toute extension exige
  un dénominateur et des renvois de preuve vérifiables.
- **Coûts natifs**. Les mesures historiques justifient de séparer
  lancement, précontrôle, HTTP et finalisation dans les futures traces de
  qualification. Préserver les états partiels. Éviter de faire passer le
  surcoût observé pour une régression imputée à un seul composant.
- **Omissions historiques**. Conserver les deux pertes lexicales et les
  deux exclusions par plafond comme cas de référence. Pour les 12
  absences de candidat, maintenir les préconditions inconnues.

Les rapports et journaux sont conservés sous `data/qualification/m42b.*`,
hors Git. La qualification à six environnements demeure partielle. Les
stratégies, outils et budgets restent ceux de la base.

### Validation M4.2b

- Rejeu des deux manifestes d'archives, 135 et 176 fichiers, sous Python
  3.12.15 et 3.14.6. Les projections sont identiques hors chronométrage.
- Le banc HTTP ferme les neuf listeners sur chacun des deux Python.
  Les tests existants du lecteur passent (5/5 par version).
- Les suites régulières passent sous les deux versions avec 1 457 réussites
  et 121 tests ignorés chacune (122,02 s en 3.12 et 131,80 s en 3.14).
  Le premier essai 3.14 avait deux échecs liés à l'umask 077 hérité dans
  les tests de permissions. L'essai 3.12 associé a été interrompu.
  Les relances utilisent l'umask 022 dans le processus de test et
  conservent les journaux dans un répertoire privé.
- Les essais hôte restent séparés de la suite régulière. Le lot
  CLI/isolation/runtime donne trois échecs et quatre réussites par Python.
  Le lot worker Chromium donne cinq réussites par Python, puis quatre
  réussites supplémentaires par Python sur les deux répétitions HTTP/TLS.
- Ruff, formatage, Pyright sur le dépôt et le banc, liens locaux et
  `git diff --check` passent. Aucun scan externe, lancement de scanner
  ou changement de stratégie, d'outil ou de budget.

## M4.2c — Fiabilité et restitution

Base `e2493de`. L'exécution active des trois laboratoires historiques reste
non qualifiée. Les changements portent sur le passage HTTP/navigateur dans
le CLI et la restitution des preuves locales. La stratégie, les outils, les
quotas, la configuration signée et les baselines historiques restent
identiques.

| Contrôle | Avant M4.2c | Après M4.2c |
| --- | --- | --- |
| Collecte CLI sur la fixture SPA | L'essai attendait le code 0. La collecte statique atteignait le JSON et terminait partielle avec quatre tickets, ce qui empêchait le test de poursuivre vers Chromium. | Le code 3 conserve `partial/coverage_partial` et le motif `non_html`. L'essai interprète l'état puis appelle explicitement le navigateur. Sur HTTP et TLS, deux navigations et une observation API sont restituées. Neuf tickets et neuf reçus sont vérifiés. Le rapport reste partiel. |
| Arrêt et reprise | La fixture retenait la réponse JSON dès la collecte statique. Le scénario d'arrêt ne s'exécutait pas au bon stade. | La fixture retient maintenant la lecture du navigateur. Arrêt, refus de reprise implicite et reprise explicite sans rejeu sont vérifiés. |
| Arrêts de sécurité | `browse` pouvait remplacer un motif d'arrêt de sécurité par `browser_discovery`. | Les trois motifs persistés sont rendus tels quels avant toute nouvelle navigation ou requête, avec ou sans `--resume`. |
| Projection de l'incertitude | 54 cas génériques dans les ledgers M2.7.1. La carte seule expose des ressources `observed`. | `map-report --context-run-id` relie les 54 cas à la carte, à la source et au reçu exact. Les états sans lien restent dans le ledger. La carte historique demeure inchangée. |
| Périmètre W6 | 31 reçus de découverte et zéro des 102 reçus d'énumération. | Mêmes dénominateurs. Les preuves de la vue contexte/carte restent dans une restitution explicite avec leurs liens. |
| Lexique JavaScript | Deux omissions liées au token long du bundle historique. | Les omissions historiques restent reproductibles. Les tests synthétiques vérifient limite de token, commentaire ou chaîne incomplets, octet UTF-8 invalide et absence d'expansion du front sur un reçu tronqué. Une chaîne malformée peut encore produire une référence vérifiable. Ce cas connu fait l'objet d'un `xfail(strict=True)`. |

Les trois essais CLI passent sous chaque Python (81,69 s en 3.14 et
72,28 s en 3.12). Le journal 3.14 conserve une trace de diagnostic
`faulthandler` à 30 s pendant le test hôte, lequel finit avec succès.
L'enveloppe signée n'a pas été relevée. L'explication du statut partiel est
émise sur stderr et le JSON conserve son contrat. Le passage au navigateur
reste une action explicite. Voir le
[contrat navigateur](WEB_BROWSER_RUNTIME.md) et l'[index W6](WEB_CLIENT_REPORT.md).

La vue contextuelle vérifie les deux rapports et exige une même mission et
un ledger terminal. L'association à un nœud requiert le même identifiant
de reçu, la même empreinte et une source portée par le nœud. Les cartes
existantes sont vérifiées selon leur projection d'origine. Le nouveau champ
de restitution reste optionnel. Le rejeu des 135 et 176 fichiers des
baselines produit les mêmes composantes sémantiques qu'en M4.2b, avec les
54 liens supplémentaires dans la vue contextuelle.

### Coûts observables

Le banc relève le temps écoulé et le temps CPU de chaque lecteur hors ligne,
y compris Network, Context, plan, Fingerprint, carte, reçus et exports W6.
La vue combinée prend 1,299–1,308 s pour Juice Shop, 0,526–0,531 s pour
crAPI et 0,376–0,393 s pour DVWA sur les deux rejeux locaux. Ce temps inclut
les deux vérifications. Il ne mesure pas le seul coût du rapprochement.

Pour les étapes natives, les archives fournissent des marqueurs de fin
mais pas les heures de début de chaque adaptateur. Le banc expose les
intervalles entre marqueurs en tant que tels. Exemple M2.7.1 sur Juice
Shop : 112,855 s de la création du run à la fin de la première étape puis
7,563 s jusqu'à la fin de la suivante. Ces intervalles peuvent contenir
l'attente et les coûts du runtime. La durée native et le coût CPU/RAM par
adaptateur pendant une mission restent non mesurés.

### Limites et recommandations

- Maintenir l'état `partial` et ses raisons dans les intégrations qui
  enchaînent explicitement collecte et navigateur. Le retour 3 exige une
  interprétation du rapport. Les arrêts de sécurité conservent leur
  terminalité et le budget reste celui du mandat.
- Étudier séparément un traitement prudent des chaînes malformées et du
  signal `parser_limited`. Les tests ajoutés reproduisent le défaut sans
  changer la sélection des références.
- Conserver la séparation entre les preuves W6 et celles de l'énumération.
  Étendre un rendu uniquement avec des liens d'intégrité explicites.
- Les essais actifs sur les laboratoires historiques, leur reset et leur
  nettoyage, l'inventaire TCP actif, le coût des adaptateurs et le trafic
  physique restent hors de la qualification de cette tranche.

Les résultats détaillés et journaux sont privés sous
`data/qualification/m42c.*`.

### Validation M4.2c

Les suites régulières `python -m pytest -q -o faulthandler_timeout=30`
donnent **1 466 réussites, 121 ignorés et un échec attendu** sous Python
3.12.15 et 3.14.6 (125,14 s et 128,76 s). La sélection hôte
`tests/test_web_browser_cli_network.py` donne trois réussites par Python.
Les deux rejeux archivés conservent les empreintes, les 17 chemins examinés,
les 16 omissions et le périmètre historique de W6. Ruff, formatage, Pyright
sur le dépôt et le banc, liens locaux et `git diff --check` passent.

## M4.2d — Délimitation lexicale et consolidation

Base `9490819`. Le tokenizer garde ses règles d'extraction. La couche de
lecture traite comme ambigu un délimiteur de chaîne laissé hors des tokens,
un saut de ligne non échappé dans une chaîne simple, un commentaire de bloc
non clos ou un flux UTF-8 invalide. Dans ces cas, le script marque
`parser_limited` et aucune de ses références ne peut être programmée.
La collecte garde le reçu source, sa classification et l'état partiel.

Un token bien délimité qui dépasse la limite existante est ignoré avec
`parser_limited`. Les autres tokens valides du script restent exploitables
selon les mêmes règles qu'avant. Un reçu tronqué garde
`response_incomplete`. Les références JavaScript retenues sur son préfixe
restent des observations statiques et le front ne s'étend pas. Les tests
vérifient les cas malformés avec et sans guillemet final, les commentaires
incomplets, l'UTF-8 invalide, une continuation CRLF correctement échappée
et un template multiligne simple.

La lecture reste une analyse lexicale limitée. Elle ne valide pas la
grammaire complète de JavaScript ni les expressions régulières et templates
arbitraires. Une construction que le tokenizer ne sait pas délimiter peut
réduire la couverture. Aucun seuil ni budget signé ne change.

### Comparaison avant et après

Le [banc lexical](../../benchmarks/recon_v2/lexical.py) relit les trois
bundles archivés après vérification du manifeste, et cinq cas synthétiques
identiques de part et d'autre de la correction. Chaque cellule contient
15 mesures de temps écoulé et de CPU, avec médiane et plage dans le rapport
privé. Le banc ne réexécute aucune mission. Il vérifie la stabilité des
sorties entre répétitions et enregistre des empreintes plutôt que des URL.
Les huit empreintes d'entrée concordent sous chaque Python. Aucune nouvelle
référence vérifiable n'apparaît dans ce corpus.

```bash
umask 077
sortie=$(mktemp -d data/qualification/m42d.XXXXXX)
.venv/bin/python -B -m benchmarks.recon_v2.lexical \
  --archives .argos/qualifications > "$sortie/lexical.json"
```

| Entrée | Références vérifiables avant → après | Temps écoulé médian Python 3.12 | Temps écoulé médian Python 3.14 |
| --- | ---: | ---: | ---: |
| Synthétique ordinaire | 1 → 1 | 0,038 → 0,032 ms | 0,063 → 0,076 ms |
| Synthétique long, près de 2 Mio | 1 → 1, analyse limitée des deux côtés | 513,63 → 497,27 ms | 482,75 → 491,45 ms |
| Chaîne malformée | 1 → 0 | 0,057 → 0,008 ms | 0,050 → 0,013 ms |
| Chaîne tronquée après un appel | 1 → 0 | 0,035 → 0,023 ms | 0,026 → 0,047 ms |
| Octet UTF-8 invalide | 1 → 0 | 0,040 → 0,003 ms | 0,022 → 0,005 ms |
| Juice Shop, bundle principal | 25 → 25 | 196,41 → 211,26 ms | 190,97 → 200,79 ms |
| Juice Shop, bundle vendor | 0 → 0 | 279,80 → 288,08 ms | 295,61 → 303,15 ms |
| crAPI, bundle vendor | 0 → 0 | 174,19 → 178,45 ms | 185,85 → 180,45 ms |

Les trois cas ambigus passent de `parser_limited=false` à
`parser_limited=true`. Les trois bundles gardent respectivement 107, 5 et
1 références totales. Les écarts de temps sont descriptifs. La médiane du
bundle principal augmente d'environ 5 à 8 % selon l'interpréteur. Ces mesures
ne permettent pas d'estimer un p95 ni le coût d'une mission.

Les deux manifestes historiques (135 et 176 entrées) restent valides.
La comparaison des projections hors ligne confirme les 17 chemins
examinés, les 16 omissions, les 54 liens contextuels et l'index W6 de
31 reçus de découverte, avec les 102 reçus d'énumération hors index.
Le rejeu lexical conserve les deux omissions historiques liées au token
trop long. Les rapports privés sont rangés sous
`data/qualification/m42d.*`.

### Bilan consolidé et intégration future

| Lot | Résultat consolidé |
| --- | --- |
| M4.1 | Corpus de trois laboratoires historiques et trois fixtures bénignes, images et références indépendantes figées. |
| M4.2a | Localisation des 16 omissions et des 54 divergences entre ledger et carte. Rejeu reproductible des preuves. |
| M4.2b | Qualification partielle. Fixtures HTTP, worker DOM/API et contrôles d'isolation exercés. Trois échecs CLI par Python consignés. |
| M4.2c | Trois essais CLI réussis par Python avec état partiel conservé. Arrêts de sécurité maintenus. Vue de carte avec contexte, limites W6 et mesures des lecteurs hors ligne. |
| M4.2d | Anomalie de délimitation reproduite puis corrigée. Cas ambigu limité sans référence vérifiable. Comparaison du même corpus avant et après, preuves et baselines intactes. |

Les campagnes actives sur les trois laboratoires historiques, leur état
initial et leur remise à zéro, l'inventaire TCP actif et les mesures natives
par adaptateur ou par paquet restent non qualifiés. Un résultat partiel
reste partiel dans les rapports et dans la roadmap.

La branche de livraison est `feat/m4-recon-v2`. Le `main` local et
la référence distante locale `origin/main` pointent encore sur
`32b418d38f881405a0fbaf2ed46e5e0a9711ff41` au contrôle de préparation.
L'ascendance autorise une avance rapide sur cet état local. Après
validation, vérifier de nouveau les références et l'arbre de travail,
inspecter le diff de la branche et confirmer la stratégie d'intégration
sur l'état de `main` alors observé. Si une publication est autorisée,
vérifier ensuite la CI du SHA publié. Aucun merge ni push dans cette
tranche. Les archives privées et rapports de mesure restent hors Git.

### Validation M4.2d

Les suites régulières `python -m pytest -q -o faulthandler_timeout=30`
passent avec **1 475 réussites et 121 ignorés** sous Python 3.14.6
(127,58 s) et 3.12.15 (121,82 s). L'échec initial 3.12 sur le test de
reprise après crash est conservé. Le processus enfant s'est arrêté avant
`running` et son stderr n'a pas été remonté par le test. Une tentative de
rejeu a ensuite révélé une installation `pluggy` incomplète dans
l'environnement sous `/tmp`. Le test isolé et la suite complète passent
après reconstruction d'un environnement privé à partir des distributions
locales aux versions verrouillées, sans accès réseau.

Ruff, formatage, Pyright sur le dépôt et le banc, liens locaux et
`git diff --check` passent. Les essais hôte optionnels n'ont pas été
réexécutés dans cette tranche.
