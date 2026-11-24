# M2.4 — Fingerprinting Engine

## Audit et bilan comparatif

Base de développement : M2.3 consolidé sur `b8f7e80`, après `056a6ae`.
La [CI de consolidation](https://github.com/JN13012/argos/actions/runs/45500313079)
est verte sous 3.12/3.14 et pour le frontend. Le crash natif 3.12, ses preuves,
sa non-reproduction et le test de nettoyage SIGSEGV sont documentés dans le
[lot réseau](NETWORK_RECON.md#consolidation-m23--investigation-du-crash-312).

| Domaine | Avant M2.4 | Cette tranche |
| --- | --- | --- |
| Nmap | Produit, version, méthode, confiance, XML et reçus | Classification de produits explicitement sondés ; pas d'inférence depuis le seul numéro/nom de port |
| HTTP | Réponses éphémères, reçus expurgés, captures de découverte | Indices technologiques normalisés dans les reçus existants ; pas d'archive brute des en-têtes/corps |
| HTML / JS | Extraction de routes, pas d'inventaire technologique | Marqueurs HTML et déclarations JS bornés, sans exécution |
| TLS | Validation du certificat et transport, sans métadonnées conservées | Protocole négocié, cipher, ALPN et SHA-256 du certificat dans le reçu ; pas de déduction d'OpenSSL/OS depuis le cipher |
| State / Evidence | `JobStore`, `WebStore`, `EvidenceStore`, `ReconStore` | Réutilisation de ces composants, projection corrélée revalidable ; aucun second magasin d'actifs |
| Statut | Pas de résultat technologique corrélé | `confirmed`, `probable`, `contradictory`, `unknown`, version et état de version séparés |

Aucune nouvelle dépendance produit. Les bibliothèques standard Python suffisent
à cette sélection bornée de règles originales. FastAPI/Uvicorn sont déjà des
dépendances du dépôt ; l'artefact React installé sert uniquement au laboratoire.
Aucun catalogue tiers n'a été copié ni téléchargé dans une mission.

## Alternatives évaluées

Évaluation documentaire du 24 novembre 2026, sans benchmark ni qualification de
ces outils. Aucun binaire/version de ces candidats n'est adopté ou déclaré
qualifié. Leur catalogue plus large pourrait être utile après une intégration
contrôlée ; aucune comparaison de précision avec eux n'est revendiquée.

| Candidat | Intérêt documenté | Décision pour M2.4 |
| --- | --- | --- |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Plugins technologiques, Ruby, GPL-2.0 ; niveau 1 avec requête/redirections et niveaux plus actifs | Non intégré : son chemin réseau et ses plugins doivent passer par les contrôles Argos avant usage ; pas nécessaire pour extraire les observations déjà reçues |
| [Wappalyzer](https://www.wappalyzer.com/apps/) | Extension navigateur ; [API officielle](https://www.wappalyzer.com/docs/api/v2/lookup/) distante, avec consultation et scan live possible | Non intégré : pas d'envoi de données client à un fournisseur ni d'extension ajoutée au navigateur de mission ; pas d'hypothèse sur les droits/version d'un ancien catalogue libre |
| [httpx ProjectDiscovery](https://docs.projectdiscovery.io/opensource/httpx/usage) | Détection avec dataset Wappalyzer, probes HTTP/TLS, outil Go ; [licence MIT](https://github.com/projectdiscovery/httpx/blob/dev/LICENSE.md) | Non intégré : dupliquerait le transport actuel ; qualifier un mode d'analyse contrôlé avant adoption. Distinct du paquet Python `httpx` déjà dépendance d'Argos |

## Contrat et CLI

`recon fingerprint` ne lance aucune requête, aucun Nmap, DNS ou navigateur.
Il lit les observations déjà enregistrées et vérifiées. Les collecteurs HTTP
et Nmap gardent leurs autorisations signées, scopes, budgets et workers ;
aucune observation ou identification ne devient une permission de mission.
Le TLS est relevé au cours de la connexion déjà autorisée, après validation
normale du certificat. Aucun paquet ou probe TLS supplémentaire.

```bash
# Mission web seule, résultat Nmap seul, ou corrélation explicitement demandée :
python -m argos recon fingerprint --mission-id UUID_WEB
python -m argos recon fingerprint --network-run-id UUID_RECON_RESEAU
python -m argos recon fingerprint --mission-id UUID_WEB \
  --network-run-id UUID_RECON_RESEAU
python -m argos recon fingerprint-report --run-id UUID_FINGERPRINT
```

`--db` utilise la base privée existante. Les lectures de rapports historiques
n'exigent pas de réactiver un mandat révoqué : elles ne donnent aucun droit
d'exécution. Le snapshot `fingerprint-v1` reste dans `ReconStore`, les indices
et faits TLS dans les reçus `WebStore`, les produits Nmap dans `EvidenceStore`.
Les rapports conservent les UUID, missions et SHA-256 des reçus sources.
`fingerprint-report` revalide les reçus, la liaison au job et la projection ;
une projection modifiée puis réhachée est refusée. SHA-256 ne constitue pas une
signature d'authenticité face à un administrateur capable de réécrire la base.

Les résultats web sont séparés par origine. Une observation Nmap n'est liée à
une origine que si l'IP et le port correspondent exactement au profil HTTP
épinglé et lié au reçu ; aucun DNS n'est effectué à la relecture. Sans liaison,
le service conserve un identifiant `tcp://IP:port`. Deux vhosts ne sont pas
fusionnés ; un produit réseau commun peut corroborer leur service partagé,
sans démontrer leur technologie applicative interne.

## Règles, versions et confiance

Catalogue v1 : Uvicorn, nginx, Apache, IIS, PHP, Express, WordPress, Drupal,
Joomla, React, jQuery, Angular, Next.js, OpenSSH, PostgreSQL, MySQL, Redis et TLS.
Il s'agit de règles prises en charge, pas de 18 technologies toutes qualifiées
en laboratoire réel.

- HTTP : tokens de `Server` et `X-Powered-By` reconnus, sans conserver le texte
  original, cookies, credentials ou en-têtes non sélectionnés.
- HTML : générateur CMS, `ng-version`, `data-reactroot`, `__NEXT_DATA__`.
- JS : bannières de version React/jQuery et module React licencié déclarant
  `exports.version`. Pas de JS exécuté, d'AST général ou de résolution de code.
- Nmap : produit explicitement reconnu, port ouvert, méthode `probed` et
  confiance Nmap ≥ 7. Un service provenant de `table` reste inconnu.
- TLS : version du protocole réellement négociée ; plusieurs versions TLS
  observées peuvent coexister, contrairement aux versions logicielles ambiguës.

Une seule source donne `probable`, confiance conventionnelle 0,6. La
corroboration requiert deux familles de sources et deux reçus différents :
`confirmed`, 0,9. Les duplications d'un même reçu ne renforcent pas la confiance.
Le TLS négocié est un fait direct `confirmed`, 1,0. Des versions logicielles
incompatibles donnent `contradictory`, 0,0, sans version sélectionnée. Une
absence d'indice donne `unknown`, pas une conclusion d'absence de technologie.
Ces nombres ne sont pas des probabilités calibrées. `confirmed` signifie
corroboré selon ces règles, pas vérification du code serveur ou vulnérabilité.

Versions : uniquement nombres explicitement documentés, sans compléter un
patch absent. Un seul reçu versionné reste `probable` même si la technologie
est corroborée ; deux reçus versionnés concordants peuvent la confirmer.
Aucun appariement CPE/CVE, recherche de vulnérabilité, proposition ou lancement
de test n'est ajouté. Les dataclasses `Indicator`, `EvidenceReference` et
`TechnologyObservation`, les catégories, états et identifiants stables préparent
les consommateurs M2.5/M2.6 ; ces lots ne sont pas développés.

## Bornes et limites

Au plus 256 reçus HTTP terminés par analyse et 64 jobs du run réseau explicite.
Par réponse : 100 en-têtes au plus ; 512 caractères par en-tête analysé,
262 144 octets de corps et 32 indices distincts. MIME explicite, pas de
sniffing. Une troncature est signalée ; les budgets de preuve signés continuent
de s'appliquer avant archivage des nouveaux champs. Le format de trame TLS
reste compatible avec les anciennes trames sans métadonnées TLS.

Les anciens reçus HTTP n'ont ni corps brut ni indices technologiques. Ils
restent lisibles, sans réécriture ; le résultat signale la lacune et reste
inconnu. Pas de replay automatique pour les enrichir. Un tableau vide signifie
qu'aucune observation éligible n'a été disponible, jamais absence de stack.
Les observations partielles/non terminées ne servent pas à identifier une
technologie. Le plafond HTTP choisit les premiers reçus dans l'ordre d'archive,
pas les dernières observations : historique et changements temporels peuvent
produire des contradictions que ce lot n'arbitre pas.

Les bannières peuvent être fausses, proxifiées ou masquées. nginx et Apache
peuvent coexister derrière un proxy ; leur présence n'est pas considérée comme
contradictoire par défaut. Les numéros de port, noms de fichiers seuls et
mentions textuelles ordinaires ne prouvent pas une technologie. Pas de
fingerprinting OS, moteur TLS, sessions, exécution JS ou couverture universelle.

## Qualification et mesures

L'oracle réside uniquement dans les tests. Le moteur ne lit ni le référentiel,
ni les versions des paquets de l'évaluateur ; il reçoit les réponses réelles,
les en-têtes, l'artefact JS servi et les observations Nmap. Les marqueurs et
versions sont classifiés avant comparaison avec les labels du test.

Fixtures unitaires : dix identifications correctes, zéro faux positif sur les
contrôles, un manque intentionnel (Caddy), huit versions documentées correctement
reconnues sur huit. Précision des candidats : 100 % ; rappel : 10/11. Ces chiffres
concernent ces seuls cas, pas le catalogue ou les applications client.
Les fixtures couvrent également la duplication de preuve, l'origine épinglée,
la non-fusion d'autres IP, les états inconnus, versions contradictoires,
compatibilité historique et altération d'une projection réhachée.

Laboratoire : vrai Uvicorn 0.54.0/FastAPI local, bibliothèque React 19.3.0 servie
sans exécution, TLS contraint à 1.3, certificat local explicitement approuvé.
Trois GET passent par les tickets HTTP isolés existants. Nmap `-sV` passe par
sa mission IP signée et le worker existant. Deux fausses déclarations PHP
incompatibles sont un leurre d'évaluation, pas un moteur PHP réel.

| Mesure | Résultat sous 3.12 et 3.14 |
| --- | --- |
| Technologies présentes selon l'oracle | Uvicorn, FastAPI, React, TLS |
| Identifications correctes | Uvicorn, React, TLS : 3 |
| Technologie manquée | FastAPI : 1 ; aucun marqueur pris en charge observé |
| Faux positif parmi tous les candidats | PHP : 1, état `contradictory`, aucune version sélectionnée |
| Précision de tous les candidats / rappel | 3/4 = 75 % / 3/4 = 75 % |
| Versions documentées correctes | React 19.3.0 et TLS 1.3 : 2/2 ; version Uvicorn non annoncée et laissée inconnue |
| Contradictions | Une technologie, PHP 8.2.26 contre 8.3.12, conservées comme déclarations contradictoires |
| Sources HTTP seules | Uvicorn, React, TLS et candidat PHP contradictoire |
| Sources Nmap seules | Aucune identification du catalogue sur ce laboratoire TLS |
| Corrélation HTTP + Nmap | Pas de gain de technologie sur ce laboratoire ; la corrélation nginx HTTP/Nmap est vérifiée par fixture liée aux reçus |

En excluant les candidats contradictoires, les trois identifications retenues
sont correctes sur cette fixture ; cela ne justifie pas un taux global de faux
positifs nul. Le leurre démontre la limite des déclarations distantes. Aucun
bilan n'est guidé par des endpoints attendus fournis au moteur. Les mandats
éphémères sont révoqués et tous les services arrêtés en finalizer.

## Validation de livraison

Configuration administrateur permanente chargée, avec `ARGOS_PROJECT_HOME=$PWD`,
registre d'outils et helpers déjà qualifiés. Commandes exécutées :

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -q -o faulthandler_timeout=30
ARGOS_TEST_NETWORK=1 .venv/bin/python -m pytest -xq -s \
  tests/test_fingerprinting_host.py tests/test_web_transport.py \
  -o faulthandler_timeout=30
ARGOS_TEST_NETWORK=1 /tmp/argos-stabilization-py312/bin/python -m pytest -xq -s \
  tests/test_fingerprinting_host.py tests/test_web_transport.py \
  -o faulthandler_timeout=30
git diff --check
```

- Suite régulière finale : **1 140 réussis, zéro échec, 111 ignorés** sous 3.14
  (93,86 s) et 3.12 (96,28 s). Les ignorés hôte ne constituent pas une qualification.
- Qualification hôte distincte : **56 réussis, zéro échec, zéro ignoré** par
  version, 28,66 / 29,42 s. TLS validé/non approuvé/mauvais hostname, arrêt,
  limites, entrées privées et montages sont exercés avec les vrais workers.
- CLI et mesures par source après ajout de la comparaison : **un réussi,
  zéro échec** par version, 18,24 / 18,01 s. Les analyses HTTP seule, Nmap seule
  et corrélée relisent les mêmes preuves, sans requête ajoutée.
- Ruff, formatage, Pyright (zéro erreur), liens locaux et `git diff --check`
  passent. Aucun frontend modifié, aucune dépendance ajoutée.

Journaux, rapports de mesure, empreintes et bases de fixtures archivés hors Git
dans `.argos/qualifications/m24/`. Les archives M2.3 restent conservées. Aucun
scan externe, exploitation, recherche automatisée de vulnérabilité ou essai
client. Le navigateur de pentest et tous les autres essais optionnels hôte n'ont
pas été requalifiés par cette tranche sans changement de leur code.

Décision : tranche validée sur les fixtures et le laboratoire décrits, avec
les faux positifs, manques et contradictions ci-dessus. Validation opérateur
avant merge/publication de `feat/m24-fingerprinting`. M2.5 non commencé.


## Consolidation M2.4 — 25 novembre 2026

Base `6298e8d` : manifeste privé inchangé, six rapports archivés revalidés
contre leurs reçus HTTP/Nmap et leur projection. Les quatre occurrences de
candidats contradictoires gardent `contradictory`, confiance 0, version non
sélectionnée et état de version contradictoire. Le catalogue et ses limitations
restent ceux de cette tranche ; aucune nouvelle signature.

Validation renouvelée : Ruff, formatage, Pyright et `git diff --check` passent.
Suite régulière complète : 1 140 réussis, 111 ignorés, zéro échec sous Python
3.14 (89,78 s) et 3.12 (90,49 s). Journaux privés
`.argos/qualifications/m24-consolidation/`. Les essais hôte qualifiés ci-dessus
ne sont pas réexécutés pour cette consolidation sans changement de runtime.
Décision : intégration fast-forward et publication main autorisées ; CI vérifiée
sur le commit intégré, résultat consigné dans le lot suivant.
