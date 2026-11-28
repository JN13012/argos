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
