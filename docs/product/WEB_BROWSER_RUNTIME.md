# W4.2 — Navigation de mission et découverte SPA/API

Statut : **W4.2a livré et validé localement ; W4.2b/c préparés**.
Dépendances livrées :
[runtime HTTP W2.3](WEB_HTTP_RUNTIME.md), [CLI W3.1](WEB_CLI_DISCOVERY.md),
[oracle W3.2](WEB_OPEN_REDIRECT.md), [worker navigateur W4.1](WEB_BROWSER_WORKER.md).

## Résultat attendu

Depuis une mission démarrée avec une URL seule, explorer les pages éligibles
avec le navigateur isolé, observer leurs scripts et appels API, et conserver
les liens DOM et la provenance de chaque requête dans les résultats de mission.
La première démonstration doit trouver un lien absent du HTML initial, produit
par un script qui consulte une API, puis permettre sa consultation dans le rapport.

Cette tranche fournit une découverte anonyme supplémentaire. Elle ne livre
ni un agent LLM, ni de nouvelles familles de vulnérabilités, ni un pentest
complet. Une API observée n'est pas une API testée ou une vulnérabilité.

## Écart initial et découpage de réalisation

| Point existant | Travail nécessaire |
| --- | --- |
| La configuration v2 et `HTTP_CAPABILITIES` acceptent deux capacités HTTP | Ajouter une configuration v3 et une capacité navigateur distincte ; conserver les contrats de requêtes HTTP fermés |
| `BrowserWorker.navigate` appelle un médiateur de confiance, avec réponses en mémoire dans les essais | Construire un médiateur utilisant exclusivement le runtime HTTP signé |
| `WebRuntime.run` retourne un snapshot et conserve les corps uniquement pendant l'exécution | Ajouter une remise privée et bornée de la réponse après validation du commit HTTP |
| `WebStore.finish` termine reçu, couverture, audit et ticket dans une transaction | Y lier la ressource navigateur avant de permettre sa fourniture au rendu |
| La frontière HTML et les vérifications possèdent leurs propres liens d'arrêt/reprise | Ajouter les navigations et leurs ressources aux contrôles d'arrêt, d'intégrité et de récupération |
| `web status/report` lisent un snapshot sans exécuter d'action | Étendre ces vues avec la couverture navigateur et les API observées |

## Décisions de réalisation

1. **Configuration v3 explicite.** Capacité proposée `browser.discover`, avec
   `http.discover` nécessaire au relais. Les configurations v1/v2 restent
   inchangées : aucune migration silencieuse, modification de signature ou
   activation du navigateur par une ancienne mission. La séparation des types
   doit empêcher de soumettre `browser.discover` comme un `WebRequest` HTTP.
   Le chargement, la signature et la politique doivent reconnaître v3 ensemble.
2. **Même runtime et même propriétaire.** Garder `runtime.operation()` sur toute
   la navigation ; réutiliser le verrou de base existant. Ne jamais conserver
   une transaction SQLite ouverte pendant Chromium, DNS, le réseau ou une
   attente de débit. Le médiateur reste sur le thread propriétaire. Le slot
   navigateur est distinct des slots HTTP : une mission avec concurrence HTTP
   égale à un doit fonctionner, sans attente circulaire entre parent et enfant.
3. **Chaque sortie réseau correspond à un ticket HTTP.** Lier la navigation,
   l'identifiant de ressource et le ticket avant connexion. Reprendre les
   contrôles d'origine, chemins, effets, DNS, IP, Host/SNI, TLS, débit,
   Retry-After, expiration et révocation du runtime. Aucun socket Internet dans
   le navigateur ni client HTTP de remplacement dans le médiateur.
4. **Réponse remise seulement après commit réussi.** Le passage privé doit
   contenir identifiants, empreinte du reçu et réponse complète bornée. Il est
   interne, à usage unique, sans cache général et sans corps dans le snapshot
   public. Relire activité et deadline avant remise ; si l'écriture du reçu,
   la liaison ressource ou sa vérification échouent, rien n'est fourni au
   navigateur, le runtime devient indisponible et les autres actions s'arrêtent.
5. **Deux deadlines, sans prolongation.** La durée de navigation comprend
   démarrage, attente de débit, DNS et sous-requêtes. Chaque opération enfant
   utilise la plus petite deadline : mission, navigation, requête. Un HTTP
   imbriqué ne doit pas empêcher le nettoyage du navigateur après sa deadline.
   Le médiateur vérifie aussi l'arrêt de la navigation pendant les attentes.
6. **Conserver les restrictions W4.1 pour la première tranche.** GET/HEAD,
   une origine exacte par navigation, sans cookies transmis ni authentification,
   service workers/WebSockets bloqués. Les réponses 3xx restent refusées et
   signalées comme limites. Ne pas fournir discrètement une réponse finale
   sous l'URL initiale : cela fausserait URL visible et résolution des liens.
   Les redirections et sessions font l'objet de W4.3 avant une couverture plus
   large des applications réelles. Les origines découvertes ne s'ajoutent pas
   au scope ; les CDN absents du périmètre restent bloqués et visibles.
7. **Une observation n'est pas une conclusion de sécurité.** Conserver séparément
   ressource vue, échange exécuté, liens observés et tests de vulnérabilité.
   Le rendu peut être partiel même si des requêtes HTTP ont réussi.

## Budgets signés en v3

La section `browser` est obligatoire en v3 ; `{}` sélectionne ses valeurs par
défaut. Elle valide des entiers bornés, refuse les champs inconnus et expose
ses limites dans `web plan`. Valeurs implémentées, sans changer le profil
système qualifié en W4.1 :

| Budget | Valeur de départ / plafond de cette tranche |
| --- | --- |
| Navigations par mission | 10 / 10 |
| Navigations simultanées | 1 / 1 |
| Durée d'une navigation | 30 s / 30 s |
| Ressources d'une navigation | 64 / 64 |
| Corps d'une ressource | 512 Kio / 512 Kio |
| Corps relayés par navigation | 8 Mio / 8 Mio |
| Liens exportés par navigation | 128 / 128, et bornes DOM W4.1 |

Toutes les requêtes consomment aussi les budgets HTTP de mission existants,
y compris les refus après réservation et les erreurs DNS selon leur contrat.
Le plafond de corps doit abaisser celui du worker HTTP avant téléchargement,
sans jamais l'augmenter. Les octets relayés sont un budget de transfert,
distinct du quota des preuves persistantes ; les deux sont appliqués.
Captures et liaisons nouvelles sont comptées dans le quota des preuves.
Un bundle JavaScript trop gros ou une application lente donne une limite
explicite ; ces valeurs ne prétendent pas couvrir toutes les SPA.

## État et preuves

Schéma additif proposé, dont les noms définitifs seront fixés à l'implémentation :

- Navigation : mission/run/route, propriétaire, hash de configuration et de
  profil, réservation, deadline, état et raison de terminaison, arrêt demandé.
- Ressource : navigation, numéro séquentiel, type, URL privée et empreinte,
  méthode, ticket HTTP, empreinte du reçu, état de remise et raison de refus.
- Capture : liens DOM privés bornés, empreinte, sources et tickets utiles,
  limitations ; pas de DOM complet, console, cookie ou capture d'écran par défaut.

La fin d'un échange lie atomiquement son reçu à la ressource. La fin de
navigation lie atomiquement la capture, la couverture et les candidats de
frontière après vérification des reçus associés. Un crash entre ces étapes
laisse des ressources exécutées mais une navigation interrompue, jamais un
rendu complet inventé. Les liens DOM restent des candidats soumis à la
politique avant exploration ; les endpoints fetch/XHR sont identifiés comme
API observées, avec leur provenance, sans être automatiquement déclarés testés.

La récupération ne recharge aucune page et ne renvoie aucune ressource
incertaine. Une reprise explicite peut avancer sur les navigations jamais
commencées. Rejouer une navigation interrompue exige une nouvelle tentative
identifiée et de nouveaux tickets, sans effacer son historique. Les vues
`status/report` restent strictement en lecture seule.

## Parcours CLI prévu

Conserver les commandes HTTP existantes. Ajouter d'abord une action explicite
de découverte navigateur sur un run, sans URL ou script libres :

```text
argos web browse --run-id UUID --public-key reviewer.pub.pem --json
argos web status --run-id UUID --json
argos web report --run-id UUID --json
argos web stop --run-id UUID
```

**`browse` n'existe pas encore.** Il sélectionnera les routes HTML éligibles
du run et les nouveaux candidats DOM, dans la limite signée. Les fichiers
d'installation du navigateur viennent de la configuration d'administration,
jamais de la cible ou du modèle. La sortie conserve UUID, compteurs, hashes,
états et raisons stables ; chemins et valeurs de query restent privés.
Une mission v2 demandant `browse` sera refusée clairement avant lancement.

## Contrat de livraison de W4.2a

Première tranche, sans lancer Chromium ni ajouter de trafic :

1. Définir les contrats de navigation et la section navigateur v3, sans élargir
   `HTTP_CAPABILITIES` ni permettre une requête navigateur dans `WebRequest`.
2. Mettre à jour ensemble chargement de configuration, signature et politique ;
   garder les représentations v1/v2 et les signatures existantes inchangées.
3. Ajouter le schéma de navigation/ressources et ses vérifications d’intégrité,
   avec lecture des bases anciennes sans exécution ni migration implicite en
   mode rapport.
4. Tester refus de champs/budgets invalides, capacité absente, signature
   différente, v2 utilisée pour naviguer et états incohérents ; vérifier qu’aucun
   résolveur ou worker n’est appelé par cette tranche de contrats.
5. Consigner le bilan du sous-lot et mettre à jour sa ligne de roadmap avant
   de raccorder le relais W4.2b.

### Implémentation et limites

- `browser_config.py` : configuration v3 explicite, `browser.discover` et
  `http.discover` obligatoires, budgets signés. Les capacités HTTP restent
  fermées aux deux capacités v2 ; aucune conversion navigateur → requête HTTP.
- `navigation.py` : requête liée à mission/run/route, usage, plan hors réseau
  et snapshot expurgé. `WebPolicy.navigation_preflight` recharge la signature,
  vérifie scope/effets et budgets HTTP/navigateur, borne durée et corps.
- `navigation_store.py` : tables versionnées additives de navigations et
  ressources, liaisons vérifiées à la configuration et à la frontière,
  propriété, empreintes, réservation, annulation et récupération explicite.
  Chaque écriture est une transaction courte ; aucune action réseau.
- États utilisables : `pending` → `reserved` → `cancelled` ou `interrupted` ;
  annulation depuis `pending` possible. Une réservation consomme une tentative
  même après interruption. Au plus dix lignes de planification par mission,
  y compris annulations, pour borner également les métadonnées. Les états de
  succès et les lignes de ressources sont refusés à la lecture dans cette
  tranche : le relais durable devra apporter leurs contrats et preuves.
- Le schéma de ressources est réservé pour W4.2b ; aucune ressource n'est
  encore écrite. Le hash de profil de réservation est une entrée interne de
  confiance, pas une vérification de l'installation Chromium. La qualification
  du profil réel et la réservation des octets de preuves relèvent de W4.2b.
- Une réservation contrôle à nouveau la mission dans sa transaction, partage
  l'horloge et les budgets HTTP, et utilise le slot navigateur distinct. La
  récupération explicite marque les réservations interrompues sans relecture
  de page ni attribution de succès. Elle n'est pas encore raccordée au runtime
  ou à la commande CLI ; ce raccordement appartient à W4.2b/c.
- Les lectures navigateur d'une ancienne base renvoient un usage vide sans
  créer de table. Un schéma partiel/inconnu est refusé. Initialiser un store
  en écriture ajoute les tables ; `status/report` restent sans migration.
- `web init --config` accepte v2/v3, conserve v2 par défaut ; `web plan`
  affiche les budgets v3 avec `browser_execution: not_connected`. Le reste
  du CLI continue uniquement les capacités HTTP existantes, sans navigateur.

[Exemple v3](../development/examples/web-mission-v3.json). Les représentations
v1/v2 n'ajoutent aucun champ navigateur ; les signatures lient toute la v3.
La durée de navigation peut dépasser celle d'une requête HTTP ; chaque
ressource devra néanmoins respecter les deux deadlines lors du relais.

### Validation W4.2a

Les essais de `tests/test_web_navigation.py` interdisent explicitement sockets,
DNS, worker HTTP, navigateur et lancement de worker. Ils couvrent budgets et
enveloppes invalides, anciennes configurations, signature modifiée, refus
d'effet/périmètre, durée restante, propriété, stop, concurrence, révocation,
rollback transactionnel, récupération, snapshots privés/expurgés, corruption,
schémas anciens/partiels et sortie `plan`.

Bilan du 17 novembre 2026 :

| Vérification | Résultat |
| --- | --- |
| Tests de contrats/navigation seuls | 89 réussis, réseau et workers interdits dans les essais |
| Suite complète Python 3.14.6 | 849 réussis en 175,08 s, aucun ignoré |
| Suite complète Python 3.12.15 | 849 réussis en 177,03 s, aucun ignoré |
| Ruff lint et formatage | Validés sur tout le dépôt |
| Pyright | 0 erreur, 0 avertissement |
| JSON v1/v2 comparé au code du commit `fef5ffd` | Identique sur les configurations de référence ; anciennes signatures revérifiées par les tests |
| Exemple v3, liens locaux et `git diff --check` | Validés |
| Wheel et sdist hors ligne | Construits ; nouveaux modules inclus, frontend/node_modules exclus |
| Contrats v3 depuis la wheel extraite hors checkout | Chargement et aller-retour validés |

Les deux suites complètes incluent 796 cas réguliers et 53 essais hôte.
Elles sont lancées avec la configuration hôte W4.1 existante :

```bash
ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1 ARGOS_TEST_BROWSER=1 \
ARGOS_SLIRP_PATH=/tmp/argos-network-tools/usr/bin/slirp4netns \
ARGOS_SLIRP_LIBRARY=/tmp/argos-network-tools/usr/lib/x86_64-linux-gnu/libslirp.so.0 \
ARGOS_BROWSER_CORE=/home/cyber/work/argos/tools/browser/node_modules/playwright-core \
ARGOS_BROWSER_ENGINE=/home/cyber/.cache/ms-playwright/chromium_headless_shell-1255/chrome-headless-shell-linux64 \
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
```

Même commande sous Python 3.12 en remplaçant l'interpréteur par
`/tmp/argos-stabilization-py312/bin/python`. Les chemins `/tmp` désignent les
outils provisionnés pour cet hôte ; ils ne sont pas des dépendances embarquées.
Construction : `UV_CACHE_DIR=/tmp/argos-uv-cache uv build --offline --wheel
--sdist --out-dir /tmp/argos-w42a-dist`.

Ces résultats vérifient les contrats et les régressions des workers existants.
Aucune navigation de mission nouvelle ni évaluation de détection de failles
n'a été exécutée. L'acceptation finale W4.2 reste ouverte ; elle exige W4.2b/c.

## Point de départ de W4.2b

1. Ajouter le contrat ressource/ticket et sa validation, puis lier ce contrat
   atomiquement dans `WebStore.create/finish`, avec son quota de preuves.
2. Ajouter un passage interne à usage unique du `HTTPExchange` après commit ;
   conserver le retour public de `WebRuntime.run` sans corps ni headers privés.
3. Construire le médiateur sur le thread propriétaire, sous `operation()`,
   avec contrôles d'activité parent/enfant et deadline minimale propagée dans
   attente de débit, résolution et worker ; ne pas ouvrir de transaction réseau.
4. Raccorder arrêt/récupération et transitions vérifiées. Démontrer concurrence
   HTTP égale à un, refus de remise après panne/arrêt/deadline et absence de
   relance implicite avant de préparer l'exposition CLI W4.2c.

## Ordre des commits et critères d'acceptation

- [x] **W4.2a — Contrats et configuration** : v3, budgets, modèles de navigation,
  schéma additif, intégrité et états ; aucun trafic nouveau. Régressions des
  configurations, signatures et reçus v1/v2 compris.
- [ ] **W4.2b — Relais HTTP durable** : liaison ticket/ressource, remise après
  commit, deadlines imbriquées, contrôle d'arrêt et réservation des preuves.
  Essais positifs et injections de pannes avant exposition CLI.
- [ ] **W4.2c — Découverte CLI et qualification** : `browse`, frontière DOM/API,
  vues expurgées, reprise explicite et essais Chromium + HTTP/TLS réels sur
  serveurs de test locaux. Mettre à jour installation, exemples et bilan.

Chaque sous-lot donne un commit conventionnel court. Aucun n'est déclaré
terminé sur la seule présence du code ou d'un test simulé.

Acceptation finale de W4.2 :

- [ ] Depuis l'URL seule : HTML → script → fetch JSON → lien DOM → nouvelle
  page, avec provenance vérifiable et résultat visible dans `report`.
- [ ] Chaque requête parvenue au serveur possède ticket et reçu correspondants ;
  aucun hôte auxiliaire, port interdit, autre origine ou méthode interdite contacté.
- [ ] Signature invalide/expirée, ancien profil, configuration modifiée,
  DNS interdit et certificat incorrect refusés par le même runtime HTTP.
- [ ] La concurrence HTTP égale à un fonctionne ; les compteurs navigateur
  n'affaiblissent ni cadence globale ni quota HTTP, même après redémarrage.
- [ ] Budgets de durée, ressources, corps, preuves et URL épuisés séparément :
  arrêt explicite, résultats partiels, aucune relance cachée.
- [ ] Annulation, révocation et crash pendant démarrage, attente de débit,
  connexion, réponse et commit : descendants nettoyés, historique conservé,
  aucune ressource fournie après un refus d’activité observé ou une preuve
  non validée.
- [ ] Corps, cookies et marqueurs privés absents des sorties, logs ordinaires
  et reçus publics ; bases anciennes toujours consultables.
- [ ] Suites Python 3.12/3.14, lint, typage, wheel/sdist et essais hôte passent.

## Suite vers le pentest professionnel

Le [catalogue de capacités](WEB_CAPABILITIES.md) définit les familles W5 et
leurs preuves ; la [roadmap](ROADMAP.md) porte leur ordre et leur état.
Après W4.2 : W4.3 ajoute redirections, interactions, sessions anonymes et comptes
optionnels séparés. En parallèle au sens du planning, les premières capacités
W5/W6 apportent tests méthodologiques, preuves et restitution ; il n'est pas
nécessaire d'attendre un catalogue exhaustif pour commencer W7 sur un petit
ensemble vérifié. W7 doit ensuite choisir ses hypothèses et actions, interpréter
les observations et replanifier sans intervention entre les actions prévues.
W8 mesure les résultats face aux références et à une revue experte. W9 prépare
la livraison et les pilotes clients sur un périmètre annoncé honnêtement.

Le dernier bilan W4.1, antérieur à cette préparation documentaire, est de
760 tests locaux sous Python 3.12 et 3.14. Ce nombre mesure les régressions
du logiciel ; il ne mesure pas le taux de vulnérabilités qu'Argos sait trouver.
