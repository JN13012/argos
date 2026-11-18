# W4.3 — Interactions, redirections et sessions web

Préparation et livraison du 18 novembre 2026. **W4.3a livré et validé
localement ; W4.3b livré et validé localement, W4.3c non implémenté**. Dépendances : [HTTP durable](WEB_HTTP_RUNTIME.md),
[navigateur CLI](WEB_BROWSER_RUNTIME.md) et [configuration](WEB_CONFIG.md).

## Objectif et découpage

Permettre les parcours web réels : transmettre une requête API ou un formulaire,
conserver une session isolée et franchir les redirections sans contourner les
contrôles du runtime. Le lot est livré par tranches qualifiées :

| Tranche | Résultat et critère de sortie |
| --- | --- |
| W4.3a | Requêtes structurées anonymes : configuration v4 signée, méthodes explicites, corps UTF-8 et en-têtes bornés, CLI `request` et consultation privée/expurgée ; HTTP et HTTPS réels, arrêt et récupération sans replay |
| W4.3b | Redirections navigateur : chaque saut intercepté et lié à sa preuve, URL visible exacte, contrôle d'origine, cycles et plafonds ; même traitement pour document, script et fetch |
| W4.3c | Actions de formulaire/navigation et sessions : actions typées issues d'une page vérifiée, cookies secrets séparés par identité, sessions anonymes puis identités optionnelles ; reprise et nettoyage sans fuite |

Le transport structuré précède son utilisation par le navigateur. W4.3a ne
soumet pas automatiquement les formulaires d'une page et n'active ni cookies,
Authorization, téléchargements de fichiers ou authentification. W4.3b exige
une interception qualifiée : la [documentation Playwright](https://playwright.dev/docs/network)
indique que le routage ordinaire traite une requête et ses redirections comme
un ensemble ; fournir simplement un 3xx ne prouve pas l'interception des sauts.
Le réseau direct du navigateur reste interdit. Aucun client HTTP de secours.

## Contrats W4.3a

- **Configuration v4 explicite.** `http.interact`, section `interaction`
  obligatoire : méthodes signées, `body_bytes` ≤ 16384, `header_bytes` ≤ 2048.
  Les capacités navigateur/HTTP existantes restent disponibles. Les documents
  v1/v2/v3 et leurs représentations canoniques sont inchangés.
- **DTO distinct.** `StructuredWebRequest` porte URL privée, méthode, corps
  texte UTF-8 et paires d'en-têtes immuables. Identifiants, parent, profil, IP,
  socket ou commande ne sont pas choisis par le contenu JSON de l'action.
- **Méthodes.** GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE, limitées à la liste
  de mission. Les trois premières n'acceptent pas de corps. Les autres exigent
  `effects.allow_test_writes: true`. Par défaut seules GET/HEAD/OPTIONS sont
  admises. Les chemins/actions déjà interdits par la politique conservative
  restent bloqués, y compris avec le drapeau d'écriture.
- **En-têtes.** Seulement Accept et Content-Type. Pas de doublon, contrôle ASCII,
  CR/LF refusés. Corps text/plain, application/json ou
  application/x-www-form-urlencoded, avec charset UTF-8 facultatif. Host/SNI,
  Content-Length, encodage et connexion viennent exclusivement du worker.
  Les JSON malformés destinés à un test restent des octets à envoyer ; aucune
  correction du contenu cible n'est effectuée.
- **Même chemin contrôlé.** Ticket, DNS, IP/port, TLS, débit, délais, révocation,
  preuves et quota existants. Le worker vérifie aussi ses entrées avant socket.
  Un appel = un échange ; aucun suivi automatique des 3xx ou retry d'écriture.
- **Preuve.** Corps/en-têtes dans la requête privée, sous permissions locales ;
  reçu public versionné contenant seulement méthode, tailles et empreintes.
  Un succès de transport n'est pas une vulnérabilité ni une preuve que la
  transaction métier a réussi. Un dispatch possible reste incertain après
  arrêt/crash, même sans réponse.
- **Reprise explicite.** Seulement une requête `pending` jamais réservée, après
  revalidation, avec même mission et même identité anonyme. Une requête
  interrompue ou terminée n'est pas rejouée ; un nouvel envoi explicite prend
  un nouvel UUID et consomme les budgets restants.

## Parcours CLI

Créer puis activer une mission v4 selon le parcours existant ; l'exemple
[web-mission-v4.json](../development/examples/web-mission-v4.json) présente les
sections signées. Aucun changement automatique d'une mission v3 déjà signée.

Le fichier d'entrée privé contient, par exemple :

```json
{
  "url": "https://app.example.com/api/search",
  "method": "POST",
  "headers": {"Content-Type": "application/json", "Accept": "application/json"},
  "body": "{\"query\":\"sample\"}"
}
```

```bash
chmod 600 request.json
argos web request --mission-id UUID --request-file request.json \
  --public-key reviewer.pub.pem --json
argos web request-status --request-id UUID --json
argos web request --mission-id UUID --resume-request-id UUID \
  --public-key reviewer.pub.pem --json
```

Les options d'administration réseau/CA existantes restent disponibles.
L'arrêt d'un appel au premier plan utilise SIGINT/SIGTERM ou la révocation de
mission. `web stop --run-id` reste propre aux runs de découverte ; cette tranche
ne fournit pas une annulation persistante par UUID de requête.
`request-status` lit un snapshot sans DDL, récupération ou nouvelle exécution.
Les sorties ne reproduisent ni URL, valeur d'en-tête ni corps. Le fichier est
borné, régulier, possédé par l'utilisateur, sans lien symbolique final et sans
permissions de groupe/autres. Les clés JSON en doublon sont refusées.

## Vérifications et livraison

Vérifier les contrats et signatures anciennes/nouvelles ; méthodes, médias,
doublons, CR/LF, bornes UTF-8 et plafonds signés ; refus d'écriture avant DNS ;
exactitude des octets reçus et du Content-Length ; TLS, refus de redirection,
annulation après envoi et reprise de travaux jamais commencés ; corruption
requête/profil/preuve et absence de secrets dans les vues. Ajouter des essais
CLI réels sur serveurs HTTP/TLS locaux possédés, puis suites complètes 3.12 et
3.14 avec essais hôte, Ruff, formatage, Pyright et wheel/sdist hors checkout.

Livraison : `feat(web): add structured requests`. Cette tranche ne clôt pas
W4.3 entier ; W4.3b puis W4.3c restent à réaliser.

## Bilan W4.3a

Livré : `interaction.py`, extensions de configuration v4 et DTO HTTP, politique
avant DNS, entrées privées versionnées, transport fixe enrichi et reçu expurgé
`web-redaction-v2`. Les anciens reçus et entrées v1 restent inchangés.
`NavigationStore` recharge désormais la configuration via le parseur général,
pour conserver la navigation dans les missions v4. Aucun changement de schéma
SQLite, de dépendance ou du pilote navigateur. Une requête structurée n'est pas
une route découverte automatiquement et ne devient pas un constat de faille.

Le worker prend un corps base64 dans son entrée privée, vérifie méthodes,
en-têtes, taille et UTF-8 avant de créer un socket, puis transmet les octets
exacts avec un Content-Length calculé. Le profil réel lie aussi méthode,
empreinte du corps et des en-têtes. Les corps restent uniquement dans le
fichier d'action privé, la requête privée persistée et l'entrée temporaire du
worker ; jamais dans les arguments de processus ou les reçus publics.
Le quota de preuves conserve son sens existant ; ce n'est pas un plafond sur
la taille totale de la base privée, dont la rétention relève de W9.

La consultation `request-status` lit un snapshot sans récupération. Un envoi
sans preuve terminale est indiqué comme dispatch possible dès qu'il a quitté
l'état `pending`. La reprise CLI vérifie le type et la mission, puis utilise
l'adoption de travaux jamais réservés du runtime ; une erreur ou interruption
n'entraîne jamais une nouvelle tentative cachée.

86 cas ajoutés : 54 de contrats/politique/preuves/CLI, 22 de protocole de requête
et 10 essais hôte. Les nouveaux parcours hôte vérifient JSON et formulaire sur
HTTP/TLS, frontière de 16384 octets UTF-8, méthodes supplémentaires, 3xx sans
suivi, arrêt après réception d'une écriture, certificat non fiable, adoption
pending, mort du propriétaire sans replay et navigation v4 réelle. Les entrées
et preuves corrompues, panne transactionnelle et révocation avant dispatch sont
aussi testées.

Validation du 18 novembre 2026 :

| Vérification | Résultat |
| --- | --- |
| Nouveaux contrats et protocole | 76 réussis en 2,06 s |
| Nouveaux essais hôte CLI | 10 réussis en 44,09 s |
| Suite complète Python 3.14.6 | 985 réussis en 366,18 s, aucun ignoré |
| Suite complète Python 3.12.15 | 985 réussis en 366,30 s, aucun ignoré |
| Wheel extraite hors checkout, JSON/formulaire HTTP et HTTPS | 4 réussis en 8,04 s, import depuis le paquet extrait vérifié |
| JSON canonique v1/v2/v3 | Identique octet pour octet au code du commit `b688091` sur les configurations de référence |
| Ruff, formatage, Pyright, liens et exemples | Validés ; 0 erreur et 0 avertissement de typage |
| Wheel/sdist hors ligne | Construits ; nouveaux modules inclus, sources Python/CJS comparées au checkout, frontend/node_modules exclus |

Les suites complètes comprennent 912 cas réguliers et 73 essais hôte. Elles
ont été lancées simultanément ; ces durées ne mesurent pas la performance d'un
pentest. Aucun frontend modifié et aucune CI distante revérifiée.

Commandes : reprendre les variables hôte du
[bilan W4.2a](WEB_BROWSER_RUNTIME.md#validation-w42a), activer
`ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1 ARGOS_TEST_BROWSER=1`, puis lancer
`.venv/bin/python -m pytest -xq -o faulthandler_timeout=30` et
`/tmp/argos-stabilization-py312/bin/python -m pytest -xq -o faulthandler_timeout=30`.
Les nouveaux tests sont `test_web_interaction.py`,
`test_web_interaction_transport.py` et `test_web_interaction_network.py`.
Construction : `UV_CACHE_DIR=/tmp/argos-uv-cache uv build --offline --wheel
--sdist --out-dir /tmp/argos-w43a-dist`. La qualification du paquet extrait
charge explicitement `/tmp/argos-w43a-wheel` dans `PYTHONPATH` depuis `/tmp`,
puis exécute les quatre parcours CLI JSON/formulaire HTTP/TLS. Les chemins
mentionnés décrivent cet hôte. L'avertissement uv 0.13.1 face au backend
verrouillé `<0.12` n'a pas empêché la construction hors ligne.

Limites : appels anonymes texte uniquement, pas de headers personnalisés hors
Accept/Content-Type, cookies, références de secret, multipart ou binaire. Pas
encore de soumission de formulaire pilotée par le navigateur, de sessions ou
d'agent LLM connecté. Les essais locaux ne sont ni une qualification client,
ni un score de benchmark ou une mesure de couverture OWASP.

## Préparation W4.3b — Redirections navigateur

Objectif : suivre les 301/302/303/307/308 de document, script et fetch/XHR sans
client alternatif ni faux corps final sous l'URL initiale. La configuration v5
signée et sa capacité `browser.redirects` sont explicites. La section
`redirects` est obligatoire ; `max_hops` varie de 0 à 5, avec le minimum du
plafond HTTP déjà signé. Les JSON/signatures v1 à v4 restent inchangés.
L'[exemple v5](../development/examples/web-mission-v5.json) laisse les écritures
HTTP désactivées. Le même CLI `browse` sélectionne le pilote de mission.

La [décision d'interception](../architecture/adr/0002-browser-redirect-interception.md)
retient CDP Fetch dans le pilote fixe : chaque requête est remplie ou bloquée,
jamais continuée. Les données de cible ne choisissent ni session CDP, code,
installation ou commande. Les identifiants de ressources et parents sont
bornés ; la destination enfant doit correspondre à la Location parente
normalisée, avec méthode/type conservés, parent offert et profondeur vérifiés.
Cycles et plafond arrêtent avant DNS. Origine, URL, exclusions, effets, DNS,
IP, TLS, cadence, preuves, ressources et arrêt gardent leurs contrôles existants.

Les ressources JSON v2 conservent identifiant, parent, profondeur et destination
privée, liée par empreinte au reçu HTTP versionné. Publication et preuve sont
atomiques. Une capture v2 conserve l'URL finale réelle, y compris son fragment,
liée à un document fourni. Le rapport expose seulement empreintes, identifiants
et états. Un refus ou un rendu interrompu reste limité ; aucun replay n'est
ajouté à la reprise de mission.

Critères : chaîne réelle document → script → API avec redirections sur HTTP et
HTTPS ; `location` et liens relatifs résolus depuis la vraie URL ; parent/reçu
pour chaque saut ; refus autre origine, chemin exclu/effet interdit, cycle,
plafonds et Location invalide ; arrêt/révocation et panne de preuve sans remise
ni nouvelle connexion ; cibles auxiliaires signalées en état limité ; lecture
seule et expurgation. Rejouer les suites 3.12/3.14 avec essais hôte, le paquet
hors checkout, les anciennes configurations et les vérifications statiques.

Limites prévues : GET/HEAD anonymes, une origine exacte par navigation, sans
cookies transmis. Workers, popups et iframes hors processus ne sont pas des
capacités supplémentaires : leur apparition interrompt le rendu concerné.
Les actions/sessions restent W4.3c. Commit prévu :
`feat(web): follow browser redirects`.


## Bilan W4.3b

Livraison : `feat(web): follow browser redirects`. La configuration v5 se charge
par le parseur général ; `plan` expose les limites et `cdp_per_hop`. Les anciennes
représentations canoniques v1/v2/v3/v4 ont été comparées au code de `9360d79` et
restent identiques. Aucun changement de dépendance ni de schéma SQLite.

`browser_driver.cjs` sélectionne CDP Fetch uniquement pour v5. La session
intercepte toutes les requêtes de sa page, désactive le cache et le passage par
service worker, puis remplit ou bloque. Elle n'appelle jamais continue. Les
identifiants Chromium sont traduits en entiers bornés et les sockets du relais
sont fermés lors d'un abandon. Le profil lie ces limites, le pilote et les
installations avant/après. Les anciennes missions gardent le mode précédent.

`browser_redirects.py` valide plafonds, destinations relatives/absolues,
fragments et provenance. `NavigationEvidence` conserve des ressources v2 avec
parent, profondeur et destination privée, liées à la section `browser_resource`
v2 dans le reçu HTTP. L’enveloppe HTTP anonyme reste `web-redaction-v1` ; les
requêtes structurées W4.3a gardent leur propre enveloppe `web-redaction-v2`.
Une destination enfant doit correspondre au parent effectivement offert ; une
réponse finale, un mauvais parent, cycle ou plafond ne peuvent devenir un saut
supplémentaire. Chaque exchange passe dans le même runtime HTTP avec un ticket
neuf ; le parent ne monopolise pas le slot HTTP. Les réservations de preuves
et les transferts incluent aussi les sauts. Une panne de preuve empêche toute
remise et arrête le runtime. La remise demeure `offer_attempted`, sans inventer
un accusé Chromium. Arrêt/crash ne donnent pas lieu à un replay.

La capture v2 contient l'URL réelle finale, fragment compris, seulement si elle
correspond à un document non redirectionnel offert. Un échec peut conserver une
capture limitée sans URL finale plutôt qu'annoncer un rendu achevé. Les liens
absolus proviennent du vrai DOM, avec `location`, `Response.url` et
`XMLHttpRequest.responseURL` natifs. Le rapport ajoute empreinte d'URL finale,
identifiants/parents/profondeurs et destination hachée par ressource ; aucun
chemin, query, fragment, cookie ou corps privé n'est exposé.

La catégorie fetch/XHR suit le type natif de l'événement Fetch CDP ; elle ne
prétend pas identifier avec certitude l'API JavaScript utilisée. Les deux
appartiennent aux observations API, toujours `security_testing: not_tested`.
Les workers, popups et iframes hors processus sont des cibles auxiliaires qui
limitent ce rendu, pas des moteurs réseau supplémentaires. Un worker blob est
qualifié en refus réel ; les limites d'origine et GET/HEAD demeurent explicites.

Les nouveaux cas vérifient les liens et preuves sur HTTP/TLS, les sauts de
script, fetch et XHR, URL finale et fragment, 301/302/303/307/308 et conservation
GET/HEAD dans les contrats, plafond à zéro, cycle, faux parent/destination,
ancien profil, signature modifiée, URL jointe trop longue, autre origine,
chemin interdit, changement de certificat après le parent, annulation pendant
le document redirigé, défaut de preuve et substitution de réponse. Les essais
CLI parcourent une nouvelle page DOM et vérifient dix requêtes serveur avec
dix tickets/reçus, les vues en lecture seule et l'absence de replay. Les parcours
hôte de redirection utilisent GET ; les règles HEAD sont testées au niveau des
contrats.

Validation du 18 novembre 2026 :

| Vérification | Résultat |
| --- | --- |
| Suite complète Python 3.14.6 | 1 044 réussis en 535,61 s, aucun ignoré |
| Suite complète Python 3.12.15 | 1 044 réussis en 537,31 s, aucun ignoré |
| Cas ajoutés | 46 de contrats/protocole/preuves et 13 essais hôte, repris dans les deux suites |
| CLI v5 HTTP et HTTPS depuis la wheel hors checkout | 2 réussis en 54,33 s, import depuis le paquet extrait vérifié |
| JSON canonique v1/v2/v3/v4 | Identique octet pour octet au code de `9360d79` sur les configurations de référence |
| Ruff, formatage, Pyright, syntaxe Node et liens locaux | Validés ; 0 erreur et 0 avertissement de typage |
| Wheel/sdist hors ligne | Construits ; module et pilote inclus, sources Python/CJS comparées au checkout, frontend/node_modules exclus |

Les suites complètes incluent 958 cas réguliers et 86 essais hôte. Elles ont
été exécutées simultanément ; ces temps ne sont pas des mesures de performance
de pentest. La qualification finale utilise un pilote inchangé durant chaque
navigation. Aucun frontend modifié et aucune CI distante revérifiée.

Commandes : reprendre les variables hôte de la
[validation W4.2a](WEB_BROWSER_RUNTIME.md#validation-w42a), activer les trois
options `ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1 ARGOS_TEST_BROWSER=1`, puis
lancer les interpréteurs 3.12 et 3.14 avec
`-m pytest -xq -o faulthandler_timeout=30`. Les nouveaux fichiers de tests sont
`test_web_browser_redirects.py`, `test_web_browser_redirect_protocol.py` et
`test_web_browser_redirects_network.py`. Construction :
`UV_CACHE_DIR=/tmp/argos-uv-cache uv build --offline --wheel --sdist --out-dir
/tmp/argos-w43b-dist`. L'essai du paquet importe explicitement
`/tmp/argos-w43b-wheel` via `PYTHONPATH`, depuis `/tmp`, et rejoue les deux
parcours CLI HTTP/HTTPS. Les chemins désignent cet hôte. L'avertissement uv
0.13.1 face au backend verrouillé `<0.12` n'a pas empêché la construction.

Les sessions, actions de formulaire, POST navigateur, origines multiples dans
un même rendu et comptes restent W4.3c. Aucun résultat de détection OWASP/CVE,
cible client, benchmark externe ou CI distante n'est déduit de ces essais.
