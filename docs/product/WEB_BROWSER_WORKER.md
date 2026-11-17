# W4.1 — Navigateur anonyme isolé

Le socle interne de navigation est implémenté et qualifié avec Chromium réel.
Il charge un document, exécute son JavaScript, reçoit ses ressources par un
relais contrôlé et extrait des liens ajoutés au DOM. Ce lot prépare la découverte
des applications modernes ; **il n'ajoute pas encore de commande navigateur aux
missions CLI**. Le raccordement aux tickets, signatures, compteurs et preuves
persistantes du runtime constitue W4.2.

## Chemin réalisé

```text
BrowserWorker, dans le processus de confiance
    ├── guardian → cgroups → bubblewrap sans réseau
    │                           └── Node / Playwright → Chromium
    │                                                   │ requête interceptée
    └── relais Unix privé ←──────────────────────────────┘
              │ contrôle de forme, méthode, origine, budgets, activité
              └── médiateur de confiance → réponse bornée → route.fulfill
```

`BrowserWorker.navigate` est une primitive interne : une URL, un médiateur de
confiance, un contrôle d'activité et une annulation. Aucun script, sélecteur,
commande shell, argument Chromium ou chemin de montage ne provient de la page.
Le médiateur reçoit seulement URL, méthode et type de ressource. Il ne reçoit
ni cookies, ni Authorization, ni headers, ni corps de requête du navigateur.
Les essais W4.1 utilisent des réponses en mémoire, sans serveur Internet.

Le navigateur n'a aucune interface vers le réseau de l'hôte : namespace réseau
privé, sans slirp, proxy réseau ou accès DNS. L'IPC est un unique socket Unix
monté en lecture seule, situé dans un dossier temporaire privé 0700. Le socket
et l'entrée sont privés 0600. Les sockets réseau natifs, y compris ceux qui
échapperaient à l'interception Playwright, restent dans le namespace isolé.
Une panne d'interception ne permet donc pas une connexion directe à la cible.
Ce choix repose sur l'isolation système existante ; Playwright seul n'est pas
une frontière réseau.

Chaque exécution lance un navigateur et un contexte non persistant neufs.
Aucun home, dépôt, fichier de mission, bus utilisateur ou base n'est monté.
Les seuls montages supplémentaires sont le driver fixe, les installations
Playwright et Chromium en lecture seule, et le socket du relais. Les fichiers
de l'installation ne peuvent être des liens symboliques. Le guardian vérifie
leurs empreintes, celles du driver, de Node et de l'entrée avant lancement ;
le parent compare aussi le profil après une navigation terminée. Ces hashes
locaux détectent des changements, sans constituer une chaîne de distribution
signée ni une défense contre un administrateur réécrivant le code.

Le sandbox interne Chromium est désactivé : le profil bubblewrap interdit les
nouveaux user namespaces. La frontière qualifiée est donc le worker externe,
avec namespaces, capabilities retirées, root en lecture seule et cgroups.
Ce lot n'est ni un audit du navigateur ni une qualification multi-client.

## Navigation et limites

- Une origine exacte, HTTP ou HTTPS, celle de l'URL initiale. Un autre schéma,
  hôte ou port est bloqué avant le médiateur. Les chemins/exclusions, effets,
  DNS et TLS devront être revérifiés par le runtime HTTP en W4.2.
- GET et HEAD uniquement. POST, PUT, beacon avec corps et autres méthodes ne
  déclenchent pas le médiateur. Les redirections HTTP sont refusées dans cette
  tranche : aucun suivi natif. Les pages qui en dépendent restent partielles.
- Ressources, scripts et fetch/XHR de la même origine relayés en série. Aucun
  `route.continue`, `route.fetch` ou repli sur un client réseau hôte.
- Service workers désactivés ; WebSockets fermés sans `connectToServer`.
  Téléchargements annulés, popups fermés, dialogues rejetés. Ces fonctionnalités
  ne sont pas qualifiées comme parcours couverts. Les iframes ne font pas
  l'objet d'une exploration DOM distincte.
- Cookies de réponse retirés. Aucun stockage de navigateur exporté ou réutilisé.
  Le JavaScript peut écrire son stockage éphémère ; l'essai vérifie son absence
  à l'exécution suivante. Ce mode n'est pas une session authentifiée.
- Arrêt du chargement principal à DOMContentLoaded, puis fenêtre d'observation
  fixe d'une seconde. Une observation réussie ne prouve pas que la SPA a fini
  de charger, que toutes ses API ont été vues ou que ses parcours sont couverts.

| Contrôle | Profil W4.1 |
| --- | --- |
| Mémoire / swap | 1 Gio pour tout le groupe ; swap désactivé |
| CPU / tâches | 50 % d'un cœur ; 256 tâches/threads maximum |
| Descripteurs | 1024 maximum, vérifiés par le guardian |
| Durée | 30 secondes côté parent ; service systemd à 32 secondes |
| Scratch | Deux tmpfs privés `/tmp` et `/work`, 64 Mio chacun |
| Sorties | 512 Kio pour chaque flux stdout/stderr ; dépassement = échec |
| Taille des fichiers écrits | 512 Kio par fichier, y compris dans le scratch |
| Relais | 64 demandes maximum ; requête JSON de 16 Kio maximum |
| Réponses | Corps complet de 512 Kio maximum ; total de 8 Mio |
| Headers | 100 maximum, 32 Kio utiles au total ; doublons ambigus refusés |
| DOM | 1024 éléments examinés, 128 liens, 64 K caractères de liens |

Les corps partiels, compressés, mal cadrés ou trop volumineux ne deviennent
jamais des ressources complètes. Les budgets atteints, refus du relais et délais donnent
un état partiel ou un délai explicite. Le plafond des tâches de `WorkerLimits`
passe à 256 et celui des descripteurs est configurable entre 64 et 1024 ; les
workers HTTP/Nmap conservent leurs valeurs par défaut, 16 tâches et 64
descripteurs. Leurs tests de quotas restent exécutés.

Le contrôle d'activité est interrogé avant lancement, avant et après le
médiateur, puis pendant l'attente du worker à une cadence de 250 ms. Le
médiateur est du code de confiance : il doit lui-même respecter annulation,
activité et deadlines pendant ses opérations bloquantes. Il est appelé sur
le thread propriétaire pour permettre la future transaction HTTP. Une
fonction arbitraire qui bloque indéfiniment ne constitue pas un médiateur
qualifié. W4.2 devra utiliser exclusivement le chemin HTTP supervisé.

L'annulation ferme le canal de vie du guardian et arrête les descendants.
L'essai retire l'activité ou annule pendant une boucle JavaScript infinie et
vérifie un retour en moins de deux secondes après le déclenchement. Le crash
du processus propriétaire est également testé avec disparition des processus
du cgroup. Ces bornes observées localement ne constituent pas un SLA universel.

## Observations privées et sortie expurgée

`BrowserObservation.links` contient des URLs privées issues du DOM, donc
potentiellement des secrets dans les chemins ou queries. Ce sont des candidats,
jamais des permissions d'exécution ou des constats de vulnérabilité. Le résumé
public contient seulement leur nombre, des empreintes d'URL, méthodes, types
de ressources, états de fourniture/refus et limitations. Corps, DOM complet,
titre, console, cookies et captures d'écran n'y figurent pas. Les URLs privées
ne figurent pas dans le `repr` des requêtes ou observations.

Les fichiers temporaires et sockets sont supprimés après retour. Aucun reçu
durable, rapport de vulnérabilité, score de couverture ni reprise navigateur
n'est créé par W4.1. Les missions HTTP W3 restent disponibles telles quelles.

## Installation et qualification reproductible

Dépendance séparée de l'interface React :
`tools/browser/package-lock.json` verrouille **playwright-core 1.65.1**, licence
Apache-2.0, dont le manifest désigne **chromium-headless-shell révision 1255**.
Le binaire observé rapporte **159.0.8154.6** et le parent exige sa concordance
avec ce manifest. Node système `/usr/bin/node` **22.22.1** est qualifié sur cet
hôte Ubuntu/WSL. Les versions différentes exigent une nouvelle qualification.

L'installation est une opération d'administration, jamais une action de page
ou une installation automatique pendant une mission :

```bash
npm ci --prefix tools/browser --ignore-scripts --no-audit --no-fund
node tools/browser/node_modules/playwright-core/cli.js install chromium-headless-shell
```

Le second appel télécharge le navigateur dans le cache de l'utilisateur selon
Playwright. Les dépendances système doivent déjà être provisionnées. Aucun
`sudo`, Docker ou changement de configuration système n'est effectué par Argos.
Le runtime ne recherche pas un navigateur hôte de secours. L'absence de
dépendance, une installation modifiée, un profil inattendu ou une panne du
confinement provoquent un refus.

Qualification de développement, en donnant les chemins absolus administrés :

```bash
ARGOS_TEST_BROWSER=1 \
ARGOS_BROWSER_CORE="$PWD/tools/browser/node_modules/playwright-core" \
ARGOS_BROWSER_ENGINE="$HOME/.cache/ms-playwright/chromium_headless_shell-1255/chrome-headless-shell-linux64" \
.venv/bin/python -m pytest tests/test_web_browser.py tests/test_web_browser_isolation.py -q
```

Ces variables servent aux tests, pas à la configuration signée des missions.
La suite ajoute **49 tests : 41 tests de protocole/refus et 8 essais réels**.
Les essais vérifient script chargé, fetch JSON, lien DOM dynamique, sortie
expurgée, refus d'autre origine/POST/beacon/WebSocket/service worker, absence
de datagramme STUN sur l'hôte, stockage neuf, DOM borné, redirection refusée,
deadline, annulation/révocation et nettoyage après crash.
Les essais utilisent uniquement des pages possédées en mémoire. Les cibles
client et les 12 cas du corpus W1.2 ne sont pas exécutés par ce lot.

**Bilan local : 760 tests passent sous Python 3.12 et 3.14**, dont 707 tests
réguliers et 53 essais hôte activés, avec Ruff, formatage, Pyright et contrôle
du manifest W1.2 propres. L'installation `npm ci` du lock séparé a réussi.
Les builds wheel et sdist incluent le driver fixe. L'exclusion du frontend
est corrigée dans les deux formats : la wheel passe d'environ 88 Mio à 130 Kio,
sans `node_modules` ni binaire navigateur. Un rendu JavaScript a aussi été
exécuté depuis la wheel extraite, hors du checkout Python.

## W4.2 — Raccordement aux missions et découverte SPA/API

Le [découpage de réalisation W4.2](WEB_BROWSER_RUNTIME.md) est préparé :
contrats v3, relais HTTP durable, puis CLI et qualification. Il n’est pas implémenté.

1. Ajouter explicitement la capacité navigateur à une version de configuration
   signée. Une configuration v2 existante n'autorise pas implicitement ce worker.
2. Réserver les budgets de navigation, puis associer chaque ressource à un
   ticket HTTP durable avant DNS/connexion. Réutiliser scope, effets, DNS,
   Host/SNI, TLS, cadence, Retry-After et annulation du runtime HTTP.
3. Introduire un passage privé et borné des réponses complètes vers le relais,
   sans retourner les corps dans les reçus publics. Lier captures DOM et API
   observées à ces reçus dans la même frontière transactionnelle.
4. Conserver une frontière SPA/API avec provenance, refus et états partiels ;
   rendre les observations consultables dans `web status/report`. Les URLs
   découvertes ne doivent jamais élargir le scope ou déclencher seules une action.
5. Tester redirections validées saut par saut, arrêt/revocation pendant HTTP,
   épuisement de budgets, échec de preuve, crash et reprise sans relecture
   implicite. Exposer ensuite le parcours anonyme au CLI. CDN et autres origines
   restent explicites dans la configuration ; comptes et identités viennent après.

Références examinées pour l'adaptateur : [routage et service workers](https://playwright.dev/docs/api/class-browsercontext#browser-context-route),
[routage des WebSockets](https://playwright.dev/docs/api/class-browsercontext#browser-context-route-web-socket),
[lancement Chromium](https://playwright.dev/docs/api/class-browsertype#browser-type-launch).
