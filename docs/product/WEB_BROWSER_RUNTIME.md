# W4.2 — Navigation de mission et découverte SPA/API

Statut : **W4.2a, W4.2b et W4.2c livrés et validés localement**.
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

## Parcours CLI livré

Après `init --config` en v3, activation et `run`, exécuter la découverte
navigateur sur le run existant, sans URL ou script libres :

```text
argos web browse --run-id UUID --public-key reviewer.pub.pem \
  --browser-core /opt/argos/playwright-core \
  --browser-engine /opt/argos/chromium-headless-shell --json
argos web status --run-id UUID --json
argos web report --run-id UUID --json
argos web stop --run-id UUID
```

`browse` sélectionne les routes HTML éligibles du run, vérifie les nouveaux
candidats DOM par HTTP puis les rend dans la limite signée. Les fichiers
d'installation du navigateur viennent de la configuration d'administration,
jamais de la cible ou du modèle. La sortie conserve UUID, compteurs, hashes,
états et raisons stables ; chemins et valeurs de query restent privés.
Une mission v2 demandant `browse` est refusée avant lancement. Fournir les
chemins absolus de l’installation administrée suivant le
[guide navigateur](WEB_BROWSER_WORKER.md#installation-et-qualification-reproductible) ;
les chemins `/opt/argos` ci-dessus sont des exemples, pas une installation
embarquée. Les options `--slirp`, `--slirp-library` et `--ca-bundle` restent
disponibles pour les outils et autorités provisionnés.

Après arrêt ou récupération : reprendre explicitement avec les mêmes options
et `browse --resume`. Cette action adopte uniquement les navigations `pending`
jamais réservées et les routes HTTP jamais envoyées. Elle ne rejoue aucune
navigation annulée, échouée ou interrompue. Un nouveau test de ces pages
nécessitera une nouvelle tentative explicite ; aucune commande de retry
navigateur n’est fournie par cette tranche.

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
  affichait à la clôture de W4.2a les budgets v3 avec
  `browser_execution: not_connected`. Le reste
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

## Plan exécutable de W4.2b

Plan préparé sur le commit `b1ac7f4`, puis implémenté ci-dessous. La roadmap
porte le statut courant ; les décisions et critères suivants restent applicables.
Ce sous-lot raccordera le navigateur au runtime depuis une entrée interne liée
à un run et une route. Il livrera une navigation avec ressources HTTP tracées,
une capture bornée et un résultat vérifiable. La commande `browse`, la sélection
et l'expansion des routes DOM/API et les vues CLI restent à W4.2c.

### Points vérifiés dans le code

| Point actuel | Modification à réaliser |
| --- | --- |
| `WebRuntime.run/_finish` conservent le `HTTPExchange` localement et retournent un snapshot | Passage privé à usage unique après `WebStore.finish` et vérification du reçu ; aucun corps ajouté au retour public |
| `WebStore.create/finish` n'ont pas de liaison navigateur | Création de ressource liée à la requête, puis empreinte du reçu et résultat HTTP dans les mêmes transactions que leurs écritures HTTP respectives |
| Le reçu HTTP conserve taille/statut, sans empreinte durable du corps | Ajouter pour les ressources navigateur une liaison au corps et aux headers effectivement proposés ; ne pas confondre hash du reçu et hash du contenu |
| `NavigationStore.private` refuse toute ligne de ressource et tout succès | Contrats typés, lecture vérifiée et états d'exécution ; garder lisibles les réservations W4.2a et leurs interruptions |
| `_usage` ne compte que les preuves HTTP | Inclure réservations et preuves navigateur dans le même quota de mission, sans compter deux fois le même reçu |
| `BrowserRelay`, l'entrée du pilote et l'export DOM utilisent les plafonds W4.1 fixes | Appliquer aussi toutes les limites v3 abaissées, aux tentatives/refus comme aux ressources acceptées |
| Le pilote attend le relais 12 s, le HTTP peut durer 15 s | Borne enfant au temps disponible côté navigateur et propagation de la fermeture IPC ; aucune remise tardive après abandon de la requête |
| `_active/_commit_active` et le démarrage runtime ignorent les navigations | Contrôle parent dans toutes les phases, récupération sans relecture et arrêt coordonné des descendants |

### Ordre de réalisation

1. **Liaisons et états persistants.** Étendre `navigation.py` et
   `navigation_store.py` avec des contrats internes fermés. Chaque ressource
   possède navigation, séquence, type, URL privée/empreinte, méthode, origine,
   requête HTTP éventuelle, reçu éventuel et raison stable. Refus avant ticket,
   requête réservée/exécutée et offre au navigateur sont des faits distincts.
   Une ressource refusée par le relais avant médiation doit aussi être comptée
   et observable ; borner la collecte même face à une page produisant des
   milliers de requêtes. Versionner l'évolution du schéma et migrer uniquement
   en écriture, dans une transaction ; conserver les enregistrements W4.2a.
2. **Profil et admission navigateur.** Sous `runtime.operation()`, vérifier
   configuration signée, URL de route et préconditions de navigation ; figer le
   profil réel de `BrowserWorker.profile()` avant lancement et le revérifier
   après. Réserver slot navigateur, tentative, durée et capacité de preuves
   avant lancement. Recalculer les budgets réels en transaction ; ne pas
   réutiliser les compteurs d'admission par défaut de la simple planification.
   Le profil et les limites effectives doivent inclure les plafonds signés
   abaissés ; aucun argument venant de la cible ne choisit l'installation.
3. **Relais HTTP durable.** Ajouter un contexte interne de ressource à
   `WebRuntime.submit/run`, inaccessible aux DTO d'agent. Créer la liaison
   ressource/requête avant DNS et lier le ticket à cette requête avant connexion.
   Garder une transaction courte par étape ; aucun appel réseau dans SQLite.
   Chaque ressource utilise un échange HTTP unique, jamais `run_chain` ni une
   redirection suivie en secret. Un 3xx reste tracé mais non fourni au rendu.
4. **Remise privée.** À la fin HTTP, lier atomiquement résultat, reçu et ressource.
   Lier aussi taille/empreinte du corps et des headers expurgés proposés au
   navigateur ; conserver les octets uniquement en mémoire. Après commit,
   relire les liaisons, vérifier les empreintes puis activité, délai et budget
   avant consommation unique du passage privé. Une panne ou une incohérence
   invalide le passage, empoisonne le runtime et arrête les actions en cours.
   Un objet `HTTPExchange` seul n'est pas une preuve de permission de remise.
5. **Durées et budgets de bout en bout.** Propager le minimum mission,
   navigation, requête et attente IPC dans l'admission, le débit, Retry-After,
   DNS et le worker. Le début de durée couvre aussi préparation du profil et
   démarrage ; aucune phase ne crée une nouvelle durée de navigation complète.
   Relier durée monotone en cours et échéance persistée sans prolongation.
   Avant téléchargement, borner le corps par le minimum du plafond HTTP,
   de `resource_body_bytes` et du transfert restant ; ne pas télécharger au-delà
   du budget puis seulement refuser la remise. Appliquer aussi ressources et
   liens au relais/export, sans augmenter le profil système W4.1. Le slot
   navigateur ne consomme pas un slot HTTP.
6. **Fin, arrêt et récupération.** Ajouter les états `running`, `completed`,
   `partial`, `failed` avec raisons fermées aux états W4.2a existants. Un rendu
   partiel reste partiel malgré des échanges réussis ; annulation/interruption
   ne publient pas des liens comme capture achevée. La fin lie atomiquement
   capture, couverture et ressources vérifiées. Garder cette capture disponible
   pour W4.2c, sans encore modifier la frontière ni déclarer une API testée.
   Au redémarrage, réconcilier d'abord les tickets HTTP puis les navigations ;
   conserver les échanges exécutés sans rejouer la page. Une reprise ne peut
   adopter que les travaux jamais commencés ; une nouvelle tentative prend un
   nouvel identifiant et consomme les budgets restants.

Le navigateur et le médiateur restent sur le thread propriétaire ; le verrou
runtime est conservé jusqu'au nettoyage des descendants. Les contrôles de
mission, de run et de navigation s'appliquent avant DNS, pendant les attentes,
au commit et avant remise. Une fermeture de runtime ou un échec de preuve doit
également arrêter le navigateur lorsqu'aucune requête HTTP n'est en cours.

L'état durable peut prouver qu'une réponse était autorisée et qu'une remise
a été tentée. Sans accusé de réception adéquat, il ne doit pas prétendre que
Chromium l'a reçue ou exécutée. Un crash après commit et avant remise reste
un échange exécuté, avec remise inconnue et navigation interrompue.

Le HTTP anonyme existant conserve ses contrats, reçus historiques et chemins
d'exécution. Les nouveaux champs de preuve navigateur sont versionnés et
conditionnels aux nouvelles ressources ; aucun reçu historique n'est réécrit.
Les sorties publiques ne contiennent ni corps, headers privés, chemin complet,
valeurs de query, données de capture brutes ou chemins d'installation.

### Vérifications et critères de fin

| Essai requis | Preuve attendue |
| --- | --- |
| HTML → script → fetch JSON → lien DOM via l'entrée interne | Capture liée à la navigation et à tous les tickets/reçus utiles, sans publication CLI |
| Concurrence HTTP signée égale à un | Navigation terminée sans blocage ; slot navigateur indépendant |
| Anciennes missions v1/v2 et v3 modifiée/révoquée/expirée | Refus avant lancement ou arrêt coordonné ; aucune extension implicite des droits |
| Autre origine, méthode interdite, chemin exclu, DNS interdit, TLS incorrect, 3xx | Sortie interdite non contactée ; échange 3xx enregistré sans suivre sa destination ; raisons conservées |
| Limites v3 abaissées séparément | Ressources/tentatives, corps téléchargé, transfert, durée et liens réellement bornés ; pas uniquement un tronquage du rapport |
| Quota de preuves presque épuisé et panne lors de l'admission | Réservation atomique, aucun dépassement ni ticket/liaison orphelin |
| Panne dans le commit HTTP/ressource ou lecture du reçu | Aucune réponse fournie, runtime indisponible et autres actions arrêtées |
| Corps, headers, ticket ou reçu substitués ; seconde consommation | Liaison ou usage invalide refusé avant remise |
| Arrêt pendant profil/démarrage/débit/DNS/connexion/réponse/commit/remise | Durée bornée, nettoyage, aucune remise après refus d'activité observé |
| Réponse plus lente que l'attente IPC ou fermeture de celle-ci | Enfant annulé, remise abandonnée et historique conservé ; pas de travail HTTP poursuivi jusqu'à sa seule limite de 15 s |
| Crash après réservation, après reçu et pendant capture | Aucun replay ; HTTP exécuté conservé, navigation interrompue et remise incertaine explicite |
| Réouverture en lecture seule de bases anciennes et nouvelles | Aucune DDL, récupération, relance ni modification des octets du fichier |
| Marqueurs privés dans URL/corps/headers/DOM | Absents des sorties, logs ordinaires, erreurs, repr et snapshots publics |

Exécuter les tests de contrats/pannes pendant le développement, puis Ruff,
formatage, Pyright et suites complètes Python 3.12/3.14. Ajouter des essais
hôte Chromium + HTTP/TLS locaux qui vérifient les requêtes effectivement reçues,
les cas d'arrêt et les descendants après crash ; une simulation seule ne clôt
pas ce sous-lot. Refaire wheel/sdist et une exécution depuis la wheel hors
checkout pour le nouveau chemin navigateur → HTTP. Reprendre les variables
hôte du bilan W4.2a, sans les présenter comme un nouvel essai déjà passé.

Livraison : `feat(web): connect browser relay`, avec le bilan ci-dessous et la
mise à jour de la ligne W4.2b dans la roadmap.

### Bilan d'implémentation W4.2b

Entrée interne : `BrowserNavigation(runtime, worker).navigate(run_id, route_id)`
dans `browser_runtime.py`. Elle exige une route HTML effectivement visitée,
avec reçu et capture de découverte vérifiés. Elle garde `runtime.operation()`
jusqu'au nettoyage, réserve la navigation et utilise le médiateur HTTP existant.
Le worker vient de l'administration ; aucune URL libre, installation ou commande
choisie par une page n'est introduite dans cette entrée.

| Composant | Comportement livré |
| --- | --- |
| `navigation_store.py` | Schéma navigateur v2, migration transactionnelle du marqueur v1 ; enregistrements de planification v1 conservés à l'identique et lectures sans DDL |
| `navigation_evidence.py` | Ressources bornées, liaison atomique requête/reçu, contrôle des empreintes et du propriétaire, capture/couverture, quotas et récupération ; les octets des réponses ne sont pas stockés |
| `browser_response.py` | Filtrage commun des réponses, empreintes du corps et des headers filtrés, passage privé à consommation unique ; substitution et deuxième consommation refusées |
| `runtime.py` / `store.py` | Contexte interne par ressource, même politique DNS/TLS/scope/effets/débit, ticket avant connexion et reçu lié avant passage ; contrôle du parent aux attentes et au commit |
| `browser.py` / pilote fixe | Plafonds v3 abaissés, signal de fermeture IPC privé, refus de protocole comptés, erreurs d'intégrité propagées et attente bornée des ressources avant capture DOM |
| Profil et arrêt | Identité réelle et limites effectives avant/après ; contrôle d'activité pendant le calcul des empreintes, arrêt de mission/run/navigation et descendants nettoyés |

La durée commence avant la préparation du profil. Chaque ressource est bornée
par le minimum mission/navigation/requête et une fenêtre interne de 10 s,
inférieure à l'attente IPC fixe de 12 s. La fermeture complète de l'IPC arrête
l'activité enfant ; le demi-arrêt normal d'envoi du pilote reste accepté.
Les gardes de transaction et de remise relisent l'activité ; les vérifications
pendant le calcul du profil peuvent réutiliser un état pendant au plus 50 ms,
avec événement d'annulation et échéance vérifiés à chaque appel.

Les trois états `pending`, `reserved`, `running` distinguent planification,
réservation et lancement. La fin donne `completed/observed`, `partial/limited`,
`failed` avec raison fermée, `cancelled` ou `interrupted`. Le reçu HTTP et la
ressource sont liés dans une transaction ; la capture, son empreinte et ses
sources sont liées dans une autre transaction après vérification et garde
finale. Une remise est enregistrée comme `offer_attempted` : aucun accusé de
réception d'exécution Chromium n'est inventé. Un crash conserve les échanges
et leur état de remise sans relancer la page.

Le quota de preuves inclut les lignes de planification, réservations et
captures navigateur, en plus des preuves HTTP. La réservation navigateur borne
le coût maximal des URLs/liaisons/profil/capture à partir des limites signées ;
elle est remplacée par la taille réellement conservée à la terminaison. Les
budgets de transfert comptent aussi les corps partiels ; le plafond du worker
est abaissé avant chaque téléchargement selon le transfert restant.

La capture conserve les liens candidats et les empreintes de reçus des
ressources, dont les types `fetch`/`xhr` permettent d'identifier leur provenance.
Cette tranche ne les ajoute pas à la frontière et ne modifie pas `status/report`.
À la clôture de W4.2b, `browse` n'existait pas encore et le champ CLI
`browser_execution` restait `not_connected`. W4.2c, décrit plus bas, fournit
désormais ce parcours et change ce champ de présentation.
Les restrictions GET/HEAD, origine exacte, absence d'authentification/cookies
transmis, refus de 3xx et plafonds W4.1 restent ceux de cette livraison.

Validation du 17 novembre 2026 :

| Vérification | Résultat |
| --- | --- |
| Suite complète Python 3.14.6, mêmes variables hôte que W4.2a | 880 réussis en 225,90 s, aucun ignoré |
| Suite complète Python 3.12.15, mêmes variables hôte | 880 réussis en 232,11 s, aucun ignoré |
| Cas nouveaux | 23 cas de runtime/pannes, 7 essais hôte de mission et 1 cas de protocole ; les contrats W4.2a et anciennes suites restent inclus |
| Fermeture IPC et propagation des erreurs de preuve | Cas de protocole revérifié après ajout du contrôle de fermeture, 1 réussi |
| HTTP et HTTPS depuis la wheel extraite hors du checkout | 2 réussis en 21,68 s, source importée vérifiée sous `/tmp/argos-w42b-wheel` |
| Ruff, formatage, Pyright et `git diff --check` | Validés ; 0 erreur et 0 avertissement de typage |
| Wheel/sdist hors ligne | Construits ; nouveaux modules et pilote inclus, frontend/node_modules exclus |

Les suites complètes comprennent 820 cas réguliers et 60 essais hôte.
Les essais hôte ajoutés exécutent réellement Chromium, puis les workers HTTP
sur des serveurs HTTP/TLS locaux possédés, avec IP littérale loopback dans le
profil privé signé. Ils vérifient la chaîne HTML → script → fetch → lien DOM,
les tickets, les limites abaissées de ressources et de transfert, le refus TLS,
l'annulation pendant HTTP et la mort du propriétaire avec navigateur + worker
HTTP actifs. Les cgroups sont contrôlés après le crash, puis la base est
rouverte sans replay. Le protocole et les pannes sont aussi testés séparément.
Aucun score de détection de vulnérabilités ou benchmark externe n'est déduit.

Commandes de qualification : reprendre les variables hôte du bilan W4.2a et
lancer chaque interpréteur avec `-m pytest -xq -o faulthandler_timeout=30`.
Construction : `UV_CACHE_DIR=/tmp/argos-uv-cache uv build --offline --wheel
--sdist --out-dir /tmp/argos-w42b-dist`. L'essai du paquet charge explicitement
la wheel extraite via `PYTHONPATH`, depuis `/tmp`, et rejoue les deux parcours
HTTP/TLS. Les chemins de qualification sont propres à cet hôte.

Suite immédiate W4.2c : sélection des routes depuis un run, commande `browse`,
expansion des candidats DOM/API, vues expurgées et reprise explicite des travaux
jamais commencés. L'intégration interne ne constitue pas encore ce parcours CLI.

## Ordre des commits et critères d'acceptation

- [x] **W4.2a — Contrats et configuration** : v3, budgets, modèles de navigation,
  schéma additif, intégrité et états ; aucun trafic nouveau. Régressions des
  configurations, signatures et reçus v1/v2 compris.
- [x] **W4.2b — Relais HTTP durable** : liaison ticket/ressource, remise après
  commit, deadlines imbriquées, contrôle d'arrêt et réservation des preuves.
  Essais positifs et injections de pannes avant exposition CLI.
- [x] **W4.2c — Découverte CLI et qualification** : `browse`, frontière DOM/API,
  vues expurgées, reprise explicite et essais Chromium + HTTP/TLS réels sur
  serveurs de test locaux. Mettre à jour installation, exemples et bilan.

Chaque sous-lot donne un commit conventionnel court. Aucun n'est déclaré
terminé sur la seule présence du code ou d'un test simulé.

Acceptation finale de W4.2 :

- [x] Depuis l'URL seule : HTML → script → fetch JSON → lien DOM → nouvelle
  page, avec provenance vérifiable et résultat visible dans `report`.
- [x] Chaque requête parvenue au serveur possède ticket et reçu correspondants ;
  aucun hôte auxiliaire, port interdit, autre origine ou méthode interdite contacté.
- [x] Signature invalide/expirée, ancien profil, configuration modifiée,
  DNS interdit et certificat incorrect refusés par le même runtime HTTP.
- [x] La concurrence HTTP égale à un fonctionne ; les compteurs navigateur
  n'affaiblissent ni cadence globale ni quota HTTP, même après redémarrage.
- [x] Budgets de durée, ressources, corps, preuves et URL épuisés séparément :
  arrêt explicite, résultats partiels, aucune relance cachée.
- [x] Annulation, révocation et crash pendant démarrage, attente de débit,
  connexion, réponse et commit : descendants nettoyés, historique conservé,
  aucune ressource fournie après un refus d’activité observé ou une preuve
  non validée.
- [x] Corps, cookies et marqueurs privés absents des sorties, logs ordinaires
  et reçus publics ; bases anciennes toujours consultables.
- [x] Suites Python 3.12/3.14, lint, typage, wheel/sdist et essais hôte passent.

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

## Préparation W4.2c — Découverte navigateur depuis le CLI

Tranche engagée après W4.2b : `browse --run-id` sélectionne les pages HTML
vérifiées, relève les appels `fetch`/`xhr` et ajoute les liens DOM à la frontière
HTTP avant leur rendu éventuel. Les API restent des observations, sans nouveau
test de vulnérabilité ni répétition automatique de leurs appels.

Les chemins d'installation sont des options d'administration explicites
`--browser-core` et `--browser-engine`. `--resume` adopte seulement les travaux
`pending` jamais réservés. Les navigations interrompues restent dans l'historique
et ne sont jamais rejouées. Une capture déjà validée peut alimenter la frontière
après redémarrage sans nouvelle exécution de Chromium.

La provenance DOM est ajoutée aux nouvelles routes et un marqueur d'expansion
lié à l'empreinte de capture est conservé dans le run. L'ensemble est écrit en
une transaction, compte dans le quota de preuves et reste lisible sans DDL.
Les doublons restent uniques ; le rapport conserve chaque observation même
si elle désigne une route déjà connue. Les vues publiques n'exposent que UUID,
empreintes, compteurs, états et raisons fermées.

Critères : parcours CLI HTTP et HTTPS jusqu'à une page absente du HTML initial,
preuve par requête, arrêt puis reprise explicite sans replay, bornes signées,
refus v2 avant lancement, lecture seule sans changement de base, expurgation,
suites 3.12/3.14 et paquet exécutable hors checkout. Le bilan ci-dessous sera
renseigné après exécution effective des contrôles.

### Bilan d'implémentation W4.2c

`BrowserDiscovery(runtime, worker).run(run_id, resume=False)` orchestre la
sélection et l'expansion. `BrowserNavigation.navigate(..., navigation_id=...)`
peut exécuter un identifiant existant seulement s'il est `pending`, jamais
réservé et appartient au runtime. `NavigationStore.adopt` assure le changement
de propriétaire explicite après revalidation. Le CLI vérifie la configuration
v3 avant tout lancement ; `plan` indique `browser_execution: available_via_browse`.

Le run reste `running` pendant l'alternance HTTP/navigateur pour rendre `stop`
effectif même après une première découverte terminée. `Exploration.run` peut
vider la frontière sans clore ce run. Chaque page rendue doit avoir une route
HTML et une preuve HTTP vérifiées. Une navigation déjà tentée n'est pas choisie
à nouveau ; `interrupted`, `cancelled`, échec et rendu limité restent visibles
et rendent le résultat partiel. Une installation indisponible termine le run
en état partiel avec `isolation_unavailable` ; un arrêt pendant sa préparation
reste un arrêt explicite. Un plafond atteint laisse les pages restantes
observées ou non rendues, sans annoncer une couverture complète.

Les liens DOM alimentent la frontière avec les mêmes plafonds URL/profondeur/
variantes, exclusions et contrôles d'effets. Les nouvelles routes portent
`browser_source` ; le run conserve `browser_expansions`, une liste bornée de
paires navigation/empreinte de capture. Aucune table ni migration supplémentaire
n'est nécessaire. Publication, marqueur et provenance sont transactionnels,
revalidés à la lecture et comptés avec une enveloppe JSON conservatrice dans
le quota de preuves. Un quota insuffisant annule toute l'expansion. Une panne
de stockage empoisonne le runtime ; une capture déjà committée reste disponible
et peut alimenter la frontière après récupération sans rendu supplémentaire.

Les vues `status/report` ajoutent `browser` : compteurs, états et, dans le
rapport, détails de navigations/ressources, liens observés et appels `fetch`/
`xhr`. Les identifiants de route/navigation, séquences et empreintes relient
les observations aux preuves. Les doublons restent uniques dans la frontière ;
le rapport garde chaque provenance observée. Les URL brutes, valeurs de query,
corps, cookies et chemins d'installation restent privés. Les appels API ne sont
pas réémis automatiquement : `security_testing: not_tested` distingue cette
observation des tests de vulnérabilité futurs.

Essais nouveaux : 16 cas de contrats, provenance, refus v2, budgets, révocation,
lecture seule, panne transactionnelle, préparation navigateur et récupération ;
trois essais hôte CLI
réels, dont deux parcours complets HTTP/HTTPS et un arrêt pendant un appel API
suivi d'une reprise sans replay. Les deux parcours complets vérifient sept
requêtes reçues et sept tickets/preuves : contrôle de page absente, source
HTML, document navigateur, script, API, vérification HTTP du lien dynamique,
puis rendu de cette nouvelle page. Le rapport et le statut ne modifient pas
les octets de la base. Les marqueurs privés sont absents de stdout/stderr.

Validation W4.2c des 17–18 novembre 2026 :

| Vérification | Résultat |
| --- | --- |
| Suite finale Python 3.14.6 | 899 réussis en 301,88 s, aucun ignoré |
| Suite finale Python 3.12.15 | 899 réussis en 301,66 s, aucun ignoré |
| Tests ciblés de découverte navigateur | 16 réussis en 14,55 s |
| Nouveaux essais hôte CLI Chromium/HTTP/TLS | 3 réussis en 62,02 s avant la correction de préparation ; repris dans les suites finales |
| Wheel finale extraite, HTTP et HTTPS via CLI hors checkout | 2 réussis en 45,97 s ; import depuis `/tmp/argos-w42c-wheel` vérifié |
| Ruff, formatage et Pyright | Validés sur tout le dépôt, 0 erreur et 0 avertissement de typage |
| Construction hors ligne | Wheel/sdist construits, module inclus, sources Python/CJS comparées au checkout, frontend/node_modules exclus |

Les suites finales comprennent 836 cas réguliers et 63 essais hôte. La
correction finale de préparation navigateur est incluse dans ces deux passes.
Les suites ont été lancées simultanément sur cet hôte ; leurs durées ne sont
pas des mesures de performance de pentest.

Commandes : reprendre les variables hôte du bilan W4.2a et lancer chaque
interpréteur avec `-m pytest -xq -o faulthandler_timeout=30`. Les 19 cas ajoutés
se trouvent dans `tests/test_web_browser_discovery.py` et
`tests/test_web_browser_cli_network.py`. Construction :
`UV_CACHE_DIR=/tmp/argos-uv-cache uv build --offline --wheel --sdist --out-dir
/tmp/argos-w42c-dist`. L'essai du paquet copie les essais CLI sous `/tmp`,
importe explicitement le paquet extrait via `PYTHONPATH`, puis sélectionne
les deux parcours HTTP/HTTPS ; le cas d'arrêt est exécuté dans les suites hôte.
L'avertissement du CLI uv 0.13.1 face au backend verrouillé `<0.12` n'empêche
pas la construction hors ligne. Aucun benchmark externe, cible client, score de découverte
de failles ou CI distante n'est déduit de ces essais locaux. Pas de changement
frontend, donc aucune qualification UI ajoutée.
