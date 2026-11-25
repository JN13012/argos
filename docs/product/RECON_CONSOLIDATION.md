# M2.7.1 — Consolidation de la reconnaissance avant M3

Base : `604417e`, sur `feat/m27-recon-qualification`. Deux changements produit
uniquement : fingerprinting générique et calibration de l'énumération. Aucun
LLM, nouveau scanner, frontend, framework ou développement M3.

## Audit des identifications manquées

| Cas | Observations disponibles dans M2.7 | Cause | Consolidation |
| --- | --- | --- | --- |
| Express sur Juice Shop | Pas de bannière reconnue ; Nmap `unknown`, méthode `table`, confiance 3 | Information insuffisante, pas un défaut de corrélation | Reste inconnu ; aucune déduction depuis le nom de l'application |
| Angular | Bundles complets reçus, dont un de 1 689 033 octets ; métadonnées Ivy et version runtime | Analyse abandonnée au-delà de 256 Kio ; signatures compilées absentes | Détection des champs `ɵfac` + `ɵcmp`, version `ng-version` explicitement déclarée dans le bundle |
| jQuery | Déclaration HTML d'un script CDN, sans téléchargement externe | Déclaration non interprétée | Dépendance **déclarée** sur un CDN reconnu, preuve HTML, statut probable ; aucun GET CDN ajouté |
| OpenResty / nginx sur crAPI | En-tête `Server: openresty/1.17.8.2` et produit Nmap `OpenResty web app server`, `probed`, confiance 10 | Catalogue HTTP et Nmap incomplet ; la corrélation ne recevait aucun indice éligible | OpenResty reconnu dans les deux sources ; nginx comme core du produit, sans lui attribuer la version OpenResty |
| React | Bundle complet de 1 526 224 octets avec symboles React de production | Même plafond d'extraction, absence de signature des builds minifiés | Conjonction de symboles de production ; version laissée inconnue plutôt que liée à un `x.version` d'un autre module |

La corrélation historique n'était donc pas cassée : elle ne recevait pas les
indices nécessaires. La relecture passive du **seul ancien résultat Nmap**
reconnaît maintenant OpenResty comme probable, sans trafic supplémentaire.
Les anciens rapports continuent toutefois d'exposer leur ancien résultat.

Les règles sont originales et fondées sur des contrats publics :
[champs Ivy Angular](https://github.com/angular/angular/blob/main/packages/core/src/render3/fields.ts),
[symboles React 16.13.1](https://github.com/facebook/react/blob/v16.13.1/packages/shared/ReactSymbols.js),
[OpenResty et son core nginx](https://openresty.org/en/getting-started.html),
[distributions jQuery](https://releases.jquery.com/jquery/) et
[package cdnjs](https://cdnjs.com/libraries/jquery).
Pas de signature fondée sur les noms Juice Shop/crAPI, leurs routes métier,
leurs titres ou les ressources attendues du référentiel. Un tag `<app-root>`,
un nom local `jquery.js`, une mention textuelle ou Zone.js seul ne suffisent pas.

## Bornes, provenance et compatibilité

Les nouvelles réponses utilisent `argos-fingerprint-signals-v2`. L'analyse
corrélée utilise `argos-fingerprint-v2` ; les lecteurs acceptent les anciens
rulesets et recalculent chaque rapport selon **sa** version. La carte indique
le ruleset de fingerprinting utilisé ; son absence désigne le comportement
historique. Les anciens reçus ne sont ni enrichis artificiellement ni rejoués.
Les anciennes projections réseau gardent leurs anciens résultats.

Le HTML reste borné à 256 Kio. Seul le JavaScript **déjà reçu, complet et de MIME
explicite** est analysé jusqu'à 2 Mio, le plafond HTTP usuel déjà existant.
Le transport signé peut imposer moins ; un corps incomplet ou plus grand reste
inexploité pour ces signatures. Aucun budget réseau ou transport n'augmente.
Le plafond de 32 indices reste appliqué et la limitation est indiquée.
Sur les trois bundles locaux, dix répétitions hors ligne donnent environ
5–20 ms d'analyse par fichier ; ce n'est pas une mesure de performance globale.

La version Angular vient d'une déclaration runtime précise ; celle de React
minifié reste inconnue. La version d'OpenResty n'est jamais celle de nginx.
Les contradictions de versions restent `contradictory`, confiance 0, sans
version choisie. Deux reçus d'une même famille ne suffisent pas à confirmer.
Une déclaration CDN reste distincte d'une bibliothèque effectivement chargée.
Les nombres de confiance restent conventionnels, pas des probabilités calibrées.

## WhatWeb et Wappalyzer

WhatWeb **0.6.4**, commit `d279d93042d034f3fd29d5a893d44ccc0595d3f8`, a été
exécuté sur six fichiers anonymisés, dans un conteneur Ruby séparé, réseau
**none**, sources/entrées en lecture seule, CPU/RAM/PID bornés, sans référentiel
monté. Aucun plugin GPL-2.0-or-later n'est copié dans Argos ; Ruby/Addressable
servent uniquement à ce comparatif privé.

| Entrées hors ligne | WhatWeb | Argos M2.7.1 |
| --- | --- | --- |
| Trois bundles Angular/React connus | 0/3 identifications visées | 3/3 |
| Déclaration HTML jQuery | 1/1 | 1/1, explicitement déclarée |
| Framework des deux shells HTML sans marqueur suffisant | 0/2 | 0/2 |
| Contrôle négatif textuel | Aucun positif visé | Aucun positif |

Soit 1/6 contre 4/6 couples fichier/technologie attendus sur ces fichiers.
Ce comparatif ne classe pas tous les plugins WhatWeb, leurs sorties de métadonnées
ou leur mode réseau ; aucun gain supplémentaire n'y justifie son intégration.
WhatWeb peut rester pertinent pour un autre corpus, à qualifier avant adoption.

L'[API Wappalyzer](https://www.wappalyzer.com/docs/api/v2/lookup/) peut lancer
un crawl live, y compris en repli d'une recherche absente du cache. Elle n'est
pas évaluée en ligne sur ces cibles privées. Aucune extension navigateur ni ancien
catalogue de provenance/licence incertaine n'est ajouté. Pas de comparaison de
précision Wappalyzer revendiquée, ni de nouvelle dépendance produit.

## Fiabilité de l'énumération

Les deux parcours utilisaient déjà `pipeline.enumerate_paths`. La différence
était la donnée d'entrée : seul l'historique lisait ses captures de contrôle
pour alimenter `--exclude-length` / `-fs`. Le contexte n'avait pas de `run_id`
de découverte et Gobuster s'arrêtait sur sa réponse 2xx de chemin inexistant.
ffuf continuait généralement, mais avec une liste contextuelle différente.

Un helper partagé relit maintenant au plus quatre contrôles dans seize runs
de découverte de **la même mission**. Reçu et capture vérifiés, GET terminé,
corps complet, 2xx, même répertoire de seed et empreinte de configuration liée.
Un contrôle à la racine ne calibre pas une seed `/app/`. Aucun nouveau GET de
calibration, aucune extension de scope. Les références de preuve sont archivées
et revérifiées dans les rapports contextuels ; leur altération puis réhachage
est refusée. Les filtres natifs n'effacent jamais les réponses du ledger.

Sans contrôle éligible, l'arrêt reste possible : un échec natif Gobuster reconnu
devient `partial/wildcard_precheck`, avec code de sortie et empreintes conservés.
Un arrêt opérateur ou une panne d'isolation ne sont pas reclassés ainsi.
Les profils, threads, délais, `-maxtime`, wall time worker, admissions et budgets
signés restent identiques. Aucun retry ni renouvellement de quota automatique.

Fixtures indépendantes : les deux vrais adaptateurs examinent les entrées avec
la même calibration ; un chemin générique reste suspect, un candidat réel reste
lié à sa réponse. La falsification du contrôle est refusée et son analyse hors
ligne n'ajoute aucune requête. Les anciennes fixtures sans contrôle disponible
restent partielles avec leurs mêmes coûts et leurs mêmes inconnus.

## Limites conservées

- Express sans observation exploitable, versions React minifiées non attribuables,
  scripts incomplets/au-delà des bornes et stacks sans marqueur restent inconnus.
- Bannières et déclarations peuvent être trompeuses. Un produit corroboré n'est
  pas une attestation du code installé ni un constat de vulnérabilité.
- Longueur égale ne prouve pas un contenu générique : le ledger conserve les
  reçus et la classification reste prudente. Pas de traitement universel des
  soft 404 dynamiques ou des réponses génériques JSON.
- Les erreurs de transport/isolation et les limites de frontière restent des
  états partiels. Le budget restant n'autorise pas une poursuite automatique.
- Limites réseau, comptes/sessions, rendu navigateur, bruit de cartographie et
  coût physique Nmap décrits dans M2.7 restent hors de ces deux corrections.

## Requalification applicative

Même harnais, images figées, listes intégrées, onze ressources de référence par
application et mandats neufs : 150 tickets HTTP pour **toute la mission**, 900 s,
10 requêtes/s, 32 candidats au plus, un port TCP explicite. Collecte initiale,
précontrôles et tentatives échouées restent comptés. Aucun référentiel n'est
fourni aux moteurs ; notation séparée après révocation. Les baselines privées
M2.3 à M2.7 restent intactes, notamment les 135 fichiers du manifeste M2.7.

| Application | Technologies du référentiel commun M2.7 | M2.7 | M2.7.1 |
| --- | --- | --- | --- |
| Juice Shop | Express, Angular, jQuery déclaré | 0/3 | 2/3 ; Angular probable, déclaration jQuery probable ; Express inconnu |
| crAPI | nginx, React | 0/2 | 2/2 probables ; OpenResty identifié en supplément |
| DVWA | Apache, PHP | 2/2 | 2/2, mêmes versions et confiance qu'avant |
| **Total commun** | **Sept technologies** | **2/7** | **6/7** |

Avec les parcours corrélés, OpenResty est confirmé par Nmap + HTTP, version
1.17.8.2 confirmée. Le label `resty_version` de l'image fournit une référence
indépendante. nginx ne reçoit pas cette version. PHP 8.5.12 et Apache 2.4.69
restent correctement identifiés ; Apache est confirmé avec Nmap, probable en
HTTP seul. jQuery 2.2.4 est une version **déclarée** ; aucun chargement CDN n'est
revendiqué. Angular déclare 20.2.4 dans le bundle, confiance/version probables ;
cette version n'est pas ajoutée au score de versions installées faute de manifest
indépendant exact archivé. React reste sans version. Zéro faux positif parmi
ces technologies notées ; aucune garantie universelle n'en découle.

Le rappel de l'échantillon applicatif reste le même. L'amélioration porte sur
la fiabilité de l'examen des candidats et l'identification, pas sur la découverte
de davantage de ressources réelles :

| Stratégie | Ressources examinées M2.7 → M2.7.1 | Tickets HTTP M2.7 → M2.7.1 |
| --- | --- | --- |
| Historique | 16/33 → 16/33 | 126 → 126 |
| Prédéfinie | 16/33 → 16/33 | 99 → 133 |
| Contextuelle | 17/33 → 17/33 | 76 → 133 |

Chaque ligne ajoute trois jobs Nmap ; leurs paquets/probes ne sont toujours pas
mesurés. Pour le contexte, les candidats sélectionnés examinés passent de 2/32
à 32/32 sur Juice Shop et de 5/32 à 32/32 sur crAPI ; DVWA reste à 32/32.
Sur les deux SPA, beaucoup de réponses restent génériques/suspectes, jamais
confirmées comme endpoints. Les défauts sur des candidats de transport restent
inconnus/partiels. Les requêtes supplémentaires correspondent à la liste déjà
autorisée qui n'est plus interrompue au précontrôle, pas à un relèvement de budget.

La réponse `/.well-known` de Juice Shop reste partielle, `protocol_failed`, avec
8 901 octets retenus ; **la même réponse partielle existe dans M2.7**. Ce lot
ne la transforme ni en succès ni en absence. Un premier contrôle crAPI a été
refusé pour `isolation_unavailable` : arrêt conservateur, preuve et coût conservés.
Un nouvel essai explicite indépendant reproduit le parcours complet en 38 tickets,
sans erreur d'isolation et avec 32 candidats examinés. Aucun retry du moteur.

Trois parcours contextuels complets sont aussi rejoués sous Python 3.12 : 58,
38 et 37 tickets, mêmes 7/11, 5/11 et 5/11 ressources de l'échantillon, mêmes
identifications et candidats examinés. Au total, treize missions applicatives,
26 mandats révoqués et 563 reçus HTTP revérifiés, plus leurs treize jobs Nmap.
Les captures, cartes et bilans restent dans les magasins State/Evidence existants.

Les durées détaillées sont archivées, sans classement de performance : démarrage
du laboratoire et charge système ont varié. La JVM historique crAPI saturait son
plafond de 384 Mio ; son heap a été borné à 192 Mio pour la qualification, **sans
augmenter ce plafond**, changer l'image ou les permissions. La composition M2.7
est conservée ; la composition de consolidation reste privée. Aucun changement
de configuration des missions Argos pour masquer cette difficulté de laboratoire.

Les treize conteneurs de laboratoire et leurs relais sont ensuite arrêtés.
Journaux, références, comparaison WhatWeb, bases, recettes et empreintes restent
privés dans `.argos/qualifications/m271/`, ignoré de Git.

## Validation et livraison

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -q -o faulthandler_timeout=30
export ARGOS_PROJECT_HOME="$PWD"
source "$HOME/.config/argos/environment.sh"
export ARGOS_TEST_TOOL_REGISTRY="$ARGOS_TOOL_REGISTRY"
ARGOS_TEST_NETWORK=1 .venv/bin/python -m pytest -xq -s -rs \
  tests/test_recon_network.py tests/test_context_qualification.py \
  tests/test_context_relay_host.py tests/test_fingerprinting_host.py \
  tests/test_application_mapping_host.py tests/test_web_transport.py \
  tests/test_recon_qualification.py tests/test_enumeration_consolidation.py \
  -o faulthandler_timeout=30
# Même sélection sous Python 3.12.
git diff --check
```

Sous Python 3.14.6 et 3.12.15 : **1 192 réussis, 121 ignorés** par version
pour la suite régulière (101,76 s / 98,22 s). Sélection hôte pertinente :
**87 réussis, deux ignorés** par version (196,61 s / 214,63 s). Les deux
variantes sans les binaires système restent non qualifiées ; les chemins via
registre administrateur sont effectivement exercés. Les ignorés ne valent pas
qualification. Les autres suites optionnelles, dont isolation globale et profils
réseau Deep complets, ne sont pas toutes rejouées ; leur code n'a pas changé.
Les tests de récupération SIGKILL, remise après preuve, quotas, exclusions de
scope, contradictions et falsification de projection sont inclus dans la sélection.

Un diagnostic initial sous charge a atteint la deadline de 100 ms du test de
résolveur avant sa réponse trop volumineuse (`dns_timeout` au lieu de
`dns_denied`). Les suites finales sont exécutées séquentiellement après arrêt
des applications et passent **sans modification de cette deadline** ni des budgets
du produit. Les journaux intermédiaires sont conservés séparément.

Ruff, formatage, Pyright et les liens documentaires passent. Commits fonctionnels :
`df8a906` (fingerprinting versionné) et `a2e1901` (calibration et arrêts).
Aucune régression bloquante restante dans les parcours exercés. Intégration
fast-forward de M2.7/M2.7.1 dans main et push autorisés après ces validations ;
la livraison exige également la vérification de la CI du SHA poussé.
Les limites conservées ci-dessus restent ouvertes. **M3 n'est pas commencé.**
