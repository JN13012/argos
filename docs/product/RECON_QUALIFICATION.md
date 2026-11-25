# M2.7 — Qualification multi-laboratoires

Ce bilan conserve l'état M2.7 avant publication. La [consolidation M2.7.1](RECON_CONSOLIDATION.md)
porte les corrections prioritaires, les nouvelles validations et la livraison autorisée.

Base : main `e33d08d`, branche `feat/m27-recon-qualification`. Ce lot qualifie
M2.2 à M2.6 ; aucun moteur décisionnel, LLM, nouveau scanner ou frontend.

## Protocole et périmètre de preuve

Trois applications réelles, anonymes, installées pour cet essai :

| Laboratoire | Version effectivement exécutée | Image figée |
| --- | --- | --- |
| Juice Shop | 19.0.0 | `bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d` |
| crAPI | famille historique `v1`, application identité `1.0-SNAPSHOT` | Web `crapi/crapi-web@sha256:46f532e8c403c99beb914f5b5b8c070f6364f2713d4fec570dc6b74db0b69575` ; chaque backend également figé dans l'archive privée |
| DVWA | digest gelé le 25 novembre 2026, Apache 2.4.69 / PHP 8.5.12 | `ghcr.io/digininja/dvwa@sha256:61167ec23fbf861f7d96a7beb4be3612d043d48dbc6b239d4f90d7e8cdff8115` |

crAPI v1 est une qualification de cette famille d'images, pas de crAPI récent.
La configuration est assortie au déploiement officiel historique 1.0.0 ;
`BLOCK_SHELL_INJECTION=true`, aucun chatbot ni fournisseur externe. Les images
de bases/auxiliaires et du relais sont également identifiées dans la composition
figée. Aucune nouvelle dépendance du produit : Docker et les images servent
uniquement à l'évaluation. Licences amont : Juice Shop MIT, crAPI Apache-2.0,
DVWA GPL-3.0 ; aucune intégration de leur code dans Argos.

Chaque application possède un réseau Docker **internal**, sans route par défaut.
Les bases ne publient aucun port ; les conteneurs existants d'autres projets
ne sont pas modifiés. Ce daemon ne publie pas les ports des réseaux internes :
un relais Python par laboratoire joint le service interne à un socket Unix privé,
puis un relais hôte écoute sur `127.0.0.1:32880/32881/32882`. Aucun relais n'est
attaché à un réseau externe. Les relais internes sont sans capacités Linux,
sans privilèges nouveaux, avec filesystem en lecture seule et plafonds CPU/RAM/PID.
Ce sont des équipements du laboratoire, pas un repli de transport Argos.
Les workers Argos restent les workers supervisés et confinés existants.

Le script développeur [recon_qualification.py](../../scripts/recon_qualification.py)
compose trois stratégies, avec mandat web neuf et mandat IP séparé par essai :

- `legacy` : pipeline historique complet, Nmap, découverte, calibration,
  Gobuster, ffuf et expansion finale ; fingerprinting et carte HTTP ensuite.
- `predefined` : inventaire M2.3, découverte complète, carte corrélée, plan
  M2.6 conservant l'ordre des mêmes listes, puis fingerprinting/carte finaux.
- `contextual` : même collecte et mêmes listes que `predefined`, classement M2.6
  contextualisé, puis mêmes analyses finales.

Le pipeline historique possède son propre job Nmap ; il n'est pas scanné une
deuxième fois pour fabriquer un run M2.3. Ses reçus Nmap sont vérifiés via
`JobStore` ; sa carte finale reste HTTP. Les deux autres stratégies exercent la
liaison complète inventaire M2.3 → fingerprinting → carte → plan → énumération.
C'est une différence d'interface, explicitement conservée dans la comparaison.

Conditions communes : une IP et un port TCP explicitement autorisés,
identification de services, profil Quick, corpus intégré inchangé (17 répertoires,
15 fichiers), 150 requêtes HTTP **pour toute la mission**, durée signée 900 s,
10 requêtes/s, timeout 10 s, 64 URL de frontière et profondeur 3. Pour les plans
contextuels : au plus 32 candidats, budget demandé 150 mais limité au reliquat
signé ; aucun renouvellement. Les échéances natives des outils restent appliquées.
Les essais sont séquentiels, sans identités ni écritures applicatives demandées.
Les durées sont des observations d'un poste local, pas des mesures statistiques
de performance ou un classement universel des stratégies.
Les bases applicatives ne sont pas restaurées entre ces missions GET anonymes.
Les projections initiales de statut, cartographie et technologie des deux plans
sont vérifiées équivalentes ; le captcha Juice Shop varie de 47 à 48 octets,
sans différence de faits utilisés par le plan. Les reçus restent distincts.
Ce protocole ne démontre pas l'équivalence transactionnelle de toutes les données
internes des applications ni l'absence de tout effet serveur d'un GET.

Le coût HTTP inclut **tous** les tickets : collecte initiale, calibration,
redirections, précontrôles et tentatives échouées. Nmap est compté séparément
en jobs/ports ; ses probes de service ne passent pas par le runtime HTTP et le
nombre de paquets/requêtes internes Nmap n'est pas instrumenté. Aucun « coût
réseau total en paquets » n'est inventé. Les octets retenus et de preuves, le
CPU des processus enfants et la durée sont archivés. La RAM `ru_maxrss` est un
high-water mark du processus évaluateur, pas une consommation cumulée ni un pic
par conteneur applicatif. Le trafic réel peut excéder les seuls corps retenus.

## Référentiels indépendants et notation

La commande `run` ne prend ni labels, ni solutions, ni sources applicatives.
Le moteur ne reçoit que l'URL, les autorisations signées, ses listes habituelles
et ses observations vérifiées. Les références restent dans le répertoire privé
de l'évaluateur et sont lues dans un **autre processus**, après les missions et
la révocation des mandats, avec la commande `score`. Les workers n'ont pas accès
à ce répertoire. La séparation est celle d'un harnais d'évaluation ; elle ne
prétend pas protéger d'un développeur administrateur malveillant.

Les références proviennent des fichiers réellement installés, manifests d'assets,
routes serveur et versions des images ; elles ne sont pas reconstruites depuis
les seules découvertes d'Argos. Échantillon fixe de onze ressources par application,
et chemins absents témoins. Cela mesure un rappel **échantillonné**, jamais la
couverture exhaustive d'une application. Un 302/401 examine une URL sans prouver
l'accès au contenu authentifié. Les backends privés de crAPI ne sont pas ajoutés
comme cibles à partir des observations du proxy.

La précision technologique compare les identifications probables/confirmées au
référentiel ; les contradictions sont comptées séparément. Les versions ne sont
notées que si la version installée/déclarée de référence est connue exactement.
Les réponses 2xx sur chemins absents sont comptées comme **faux positifs d'une
heuristique HTTP naïve**, pas comme des vulnérabilités ou confirmations Argos.
Les résultats d'énumération `generic_response_suspected` restent ambigus. Les
observations positives non présentes dans l'échantillon sont non notées, pas
automatiquement fausses. Zéro faux positif sur un petit échantillon ne garantit
pas une précision universelle.

Trois préessais Juice Shop sont exclus : port indisponible ; démarrage incomplet
ayant révélé le défaut de bilan ; protocole ne reprenant pas encore les exclusions
historiques des endpoints de défis. Leurs mandats sont révoqués et leurs archives
restent séparées. Les essais qualifiants portent le suffixe `r3`, avec les mêmes
exclusions de l'évaluation signées pour toutes les stratégies. Aucun résultat
issu d'un endpoint de défis ne sert à leur planification ou à leurs scores.

## Correctif nécessaire à la qualification

Un échec de transport peut conserver une réponse expurgée avec `status=null`.
M2.6 comparait ce statut à 200 dans le traitement du précontrôle UUID, provoquant
un `TypeError` lors de la reconstruction du bilan. Le correctif accepte un
précontrôle positif seulement si son statut est entier. Le reçu et l'échec restent
conservés ; aucun statut HTTP ni examen n'est fabriqué. Test ciblé avec un vrai
chemin State/Evidence, sans modification des permissions, transports ou signatures.

## Reproduction

Préparer les trois images/réseaux dédiés avec la composition figée archivée,
attendre les healthchecks, puis démarrer les relais loopback. Ne pas réutiliser
une instance exposée publiquement ou une cible d'un autre projet.

```bash
export ARGOS_PROJECT_HOME="$PWD"
source "$HOME/.config/argos/environment.sh"
.venv/bin/python -m scripts.recon_qualification run \
  --url http://127.0.0.1:32880/ --strategy legacy --output /private/essai-neuf
# Refaire avec predefined et contextual, un répertoire neuf par essai.
# Notation séparée, après fin de la mission et révocation :
.venv/bin/python -m scripts.recon_qualification score \
  --trial /private/essai-neuf/trial.json --reference /private/reference.json
```

Les anciennes archives restent dans leurs emplacements ; nouvelles bases,
mandats révoqués, recettes, digests, journaux, scores et empreintes dans
`.argos/qualifications/m27/`, ignoré de Git. Aucun secret ni rapport de cible
client n'est publié. La qualification reste sur la branche, sans merge ni push.

## Résultats des missions complètes — Python 3.14

Une mission par cellule, neuf missions valides ; les limites communes sont des
plafonds identiques, pas une obligation de consommer exactement le même nombre
de requêtes. Les résultats ci-dessous incluent la collecte initiale.

| Application | Stratégie | Ressources de l'échantillon examinées | Tickets HTTP totaux | Durée (s) | Preuves HTTP (Kio) |
| --- | --- | --- | --- | --- | --- |
| Juice Shop | historique | 6/11 | 50 | 81,640 | 226,6 |
| Juice Shop | prédéfinie | 6/11 | 41 | 62,059 | 163,6 |
| Juice Shop | contextuelle | 7/11 | 28 | 55,370 | 117,6 |
| crAPI | historique | 6/11 | 38 | 56,901 | 163,6 |
| crAPI | prédéfinie | 6/11 | 21 | 34,485 | 75,3 |
| crAPI | contextuelle | 5/11 | 11 | 25,949 | 39,3 |
| DVWA | historique | 4/11 | 38 | 55,361 | 124,8 |
| DVWA | prédéfinie | 4/11 | 37 | 50,214 | 103,4 |
| DVWA | contextuelle | 5/11 | 37 | 53,713 | 103,4 |
| **Total** | **historique** | **16/33** | **126** | **193,902** | **515,0** |
| **Total** | **prédéfinie** | **16/33** | **99** | **146,758** | **342,3** |
| **Total** | **contextuelle** | **17/33** | **76** | **135,032** | **260,3** |

Chaque stratégie ajoute trois jobs Nmap, un port ouvert vérifié par application.
Les paires prédéfinie/contextuelle partagent le même coût initial : Juice Shop
24 tickets, crAPI quatre, DVWA trois. Le coût CPU enfants relevé par mission va
de 0,171 à 0,671 s ; il s'agit du CPU des enfants récoltés par l'évaluateur, pas
du CPU total des applications Docker. Les corps conservés vont de 12,3 à
4 066,9 Kio par mission ; ce volume n'est pas le trafic physique total.

La stratégie contextuelle consomme 23 tickets de moins que la prédéfinie, mais
le rappel n'augmente que d'une ressource sur l'échantillon agrégé. Elle manque
`robots.txt` sur crAPI, trouvé par les deux autres stratégies. Elle atteint
d'autres assets sur Juice Shop et DVWA. **Aucun gain systématique de couverture.**
Une partie de l'économie vient de l'arrêt de Gobuster sur les précontrôles SPA,
qui laisse davantage de candidats non examinés ; ce n'est pas une preuve
d'efficacité à couverture égale.

| Application | Collecte HTTP | Énumération prédéfinie : examinés / sélectionnés | Contextuelle : examinés / sélectionnés | Motif final d'énumération |
| --- | --- | --- | --- | --- |
| Juice Shop | 24 | 15/32 | 2/32 | `tool_or_policy_limit`, précontrôle générique Gobuster |
| crAPI | 4 | 15/32 | 5/32 | `tool_or_policy_limit`, précontrôle générique Gobuster |
| DVWA | 3 | 32/32 | 32/32 | `explicit_plan_completed` |

Les 32/32 sur DVWA incluent des 404 et redirections : ils ne signifient pas
32 ressources présentes ni un accès authentifié. La découverte historique
reste `coverage_partial` ; le pipeline termine `bounded_pipeline_finished`.
Ces motifs décrivent des étapes différentes et ne valent pas un « succès complet ».
Aucun essai valide n'atteint le plafond signé de 150 tickets. Les profils ne
sont pas prolongés pour consommer les requêtes restantes.

Précision et ambiguïtés :

- Sur DVWA, Apache et PHP ont leurs versions 2.4.69 et 8.5.12 correctes pour les
  trois stratégies ; deux vrais positifs, zéro faux positif. Apache reste probable
  dans l'analyse HTTP seule du pipeline historique, puis devient **confirmé**
  avec les sources Nmap + HTTP des deux autres parcours. PHP reste **probable**.
  Les répétitions d'une même famille de bannière ne deviennent pas artificiellement
  des sources indépendantes. La corrélation réseau/HTTP apporte ici un gain démontré.
- Juice Shop : zéro technologie reconnue sur trois attendues (Express, Angular,
  dépendance jQuery déclarée par la page). crAPI : zéro sur deux (Nginx/OpenResty,
  React). Précision non définie en l'absence de positif ; le rappel technologique
  global de cet inventaire fini est 2/7 par stratégie, pas 100 %.
- Aucune contradiction sur ces trois applications. La contre-épreuve TLS/React/
  Uvicorn existante conserve PHP contradictoire et FastAPI manqué ; elle est
  rejouée séparément et ne corrige pas le score des applications réelles.
- Lecture naïve « 2xx = endpoint présent » : trois/quatre/zéro chemins absents
  sur Juice Shop, cinq/cinq/zéro sur crAPI, zéro sur DVWA, dans l'ordre
  historique/prédéfinie/contextuelle. Ce sont des **chemins distincts du témoin**.
  Les précontrôles et `generic_response_suspected` empêchent leur confirmation
  automatique ; zéro faux positif parmi les observations contextuelles notées,
  avec les autres observations positives hors échantillon explicitement non notées.
- Un témoin initialement marqué absent, `/.well-known/security.txt` sur Juice
  Shop, a été rectifié après vérification du fichier et du middleware installés.
  C'est un contrôle positif supplémentaire, hors échantillon fixe de onze ; il
  ne compte jamais comme faux positif du moteur. Cette correction de l'évaluateur
  n'ajoute aucune entrée aux plans ni aux listes.

Les cartes ont zéro doublon, zéro relation pendante, zéro assertion observée
sans preuve et zéro référence de preuve non résolue sur les neuf missions.
Les liens `application contains resource` corrects de l'échantillon sont
8/8/7 pour Juice Shop, 6/6/5 pour crAPI et 5/5/5 pour DVWA (même ordre).
Ils peuvent concerner des références **inférées** encore non examinées ; ce score
de relation n'est donc pas le rappel des réponses HTTP. Les états inconnus des
cartes sont conservés : deux par mission Juice/crAPI, un sur DVWA. Les URLs
externes rencontrées restent des références hors scope, sans aucun GET externe.
Les deux stratégies M2.6 ont zéro doublon de candidat exécuté ; chaque mission
comporte un GET racine répété pour calibration/précontrôle, compté dans son coût.

## Limites priorisées avant M3

1. **P1 — Couverture des SPA et du fingerprinting.** Catalogue trop étroit,
   corps/scripts bornés, dépendances minifiées et en-têtes absents/non reconnus.
   Les technologies non identifiées restent inconnues. M3 doit pouvoir raisonner
   avec ces manques sans les assimiler à une absence de technologie.
2. **P1 — Arrêts d'outils et utilité des plans.** Les précontrôles génériques
   interrompent des groupes entiers ; le classement contextuel ne domine pas
   les listes. Le motif agrégé `tool_or_policy_limit`/`worker_failed` manque de
   précision pour choisir une suite automatique sûre. Aucune relance automatique
   ni correction spécifique à une application dans ce lot.
3. **P1 — Coût réseau et plafonds.** Les tickets HTTP sont exhaustifs, mais les
   paquets/probes Nmap et le CPU/RAM global ne le sont pas. Les budgets de profil
   réseau restent opérateur/par exécution, pas des budgets ajoutés au mandat signé.
   Toute future boucle devra conserver les plafonds existants et expliciter cette
   différence ; aucun quota n'a été affaibli ici.
4. **P2 — Qualité des graphes.** Certaines références de JS/HTML produisent des
   frontières d'application inférées ou du bruit hors scope ; un lien cohérent
   et prouvé n'est pas nécessairement un endpoint métier valide. Carte et ledger
   ne remplacent pas une validation sémantique. Le pipeline historique n'expose
   pas directement son job réseau sous l'interface de run M2.3.
5. **P2 — Étendue de qualification.** Petits échantillons, anonymat, profils
   Quick et une instance/version de chaque application. Pas de mesure statistique,
   comptes/sessions, rendu navigateur applicatif, grands corpus Standard/Deep,
   UDP/DNS/vhosts, déploiement externe ou couverture de vulnérabilités. Les profils
   réseau et anciennes baselines sont qualifiés séparément sur leurs fixtures.
   La cause du crash natif 3.12 historique reste celle documentée en M2.3 ; les
   scénarios de nettoyage testés ne prétendent pas en expliquer la cause.

Ce bilan permet d'établir les capacités et dettes réelles avant M3 ; il ne
qualifie pas un pentest autonome complet. Aucun développement M3 dans ce lot.

## Autorisations, preuves, interruption et régression

Les douze missions applicatives (neuf comparatives 3.14, trois reprises
contextuelles complètes 3.12) ont leurs **24 mandats révoqués** en fin d'essai.
Relecture indépendante de 377 reçus HTTP, des douze jobs Nmap, des cartes,
fingerprints et bilans contextuels : liaisons et empreintes cohérentes, aucune
transaction encore pending/running, aucun GET hors périmètre signé ni endpoint
d'évaluation exclu. Les trois parcours 3.12 retrouvent respectivement 7/11,
5/11 et 5/11 ressources avec 28, 11 et 37 tickets ; mêmes états et identifications
que les parcours contextuels 3.14. Leurs durées ne sont pas ajoutées à la
comparaison de stratégies 3.14.

La qualification hôte réutilise les fixtures réseau existantes :

| Profil | Paires IP/port examinées | Ouvertes | Fermées | Jobs terminés |
| --- | --- | --- | --- | --- |
| Quick | 3/3 | 2 | 1 | 1 |
| Standard | 66/66 | 4 | 62 | 4 |
| Deep | 130/130 | 4 | 126 | 6 |

HTTP et bannière SSH simulée connus, IPv4 puis IPv4/IPv6 pour Standard/Deep,
zéro paire non résolue, zéro expansion de scope. Les ports fermés sont réservés
par l'évaluateur ; le moteur n'a pas leurs labels. Ces mesures ne sont pas une
qualification de tous les services TCP possibles ni des maxima des profils.

Un nouveau test hôte tue réellement le **processus CLI par SIGKILL pendant un
GET de candidat** : cinq transactions de mission conservées, dont quatre tickets
d'énumération ; couverture sélectionnée reconstruite avec un examiné et un
interrompu. `context-recover` ne démarre aucun worker et n'envoie aucun GET.
Les deux mandats de fixture sont ensuite révoqués. Les tests de mort du parent
et cgroup vide existants, refus d'autres IP/ports/protocoles, scope exclu,
révocation, budgets et échec de remise/protocole restent exercés séparément.
Les fixtures historiques conservent leurs résultats attendus, y compris les
limitations technologiques et la contre-épreuve des réponses génériques.

Les manifestes privés M2.3 (32 fichiers), M2.4 (16), M2.5 (36) et M2.6 (38)
sont vérifiés avant et après : aucune différence. M2.2 reste vérifié par ses
tests et fixtures inchangés. Les treize conteneurs du projet `argos-m27` et les
relais hôte sont arrêtés, les trois ports loopback fermés ; données et images
restent archivées sans nettoyage destructif des baselines.

Commandes de validation :

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
  tests/test_network_recon_host.py tests/test_network_worker.py \
  tests/test_recon_network.py tests/test_context_qualification.py \
  tests/test_context_relay_host.py tests/test_fingerprinting_host.py \
  tests/test_application_mapping_host.py tests/test_web_transport.py \
  tests/test_recon_qualification.py -o faulthandler_timeout=30
# Même sélection avec Python 3.12.
git diff --check
```

Suite régulière : **1 185 réussis, 119 ignorés** par version, 92,03 s sous
3.14 et 98,04 s sous 3.12. Les ignorés sont des capacités optionnelles et ne
constituent pas une qualification. Ruff, formatage, Pyright et liens locaux
passent. La sélection hôte donne **123 réussis, deux ignorés par version**,
320,87 s sous 3.14 et 308,15 s sous 3.12 ;
les deux variantes utilisant des binaires système absents restent non qualifiées,
contrairement aux variantes par registre administrateur effectivement exécutées.
Les autres suites optionnelles, notamment navigateur complet, ne sont pas toutes
rejouées ; aucun frontend n'a changé. CI distante non exécutée, branche locale.

Conclusion : qualification locale bornée terminée, aucune régression bloquante
restante dans les parcours exercés après le correctif de bilan. Les lacunes de
couverture et les variantes non exécutées restent ouvertes dans les priorités
ci-dessus. Cela ne constitue pas une autorisation de lancer M3, ni de publier
la branche.
