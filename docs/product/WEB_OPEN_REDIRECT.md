# W3.2 — Redirection ouverte vérifiée et recontrôle

Argos vérifie désormais une première famille de comportements depuis le CLI :
une destination externe pilotée par un paramètre de query réellement découvert.
La vérification compare une référence et deux marqueurs distincts. Elle utilise
le runtime signé et le worker HTTP isolé, sans suivre les redirections de test.
Le constat confirme la navigation externe observée ; sa sévérité reste `unrated`
et son impact `external_navigation_only`, sans prétendre à une compromission
ou à un impact métier établi. Un service peut proposer cette navigation par
conception : son contexte doit encore être évalué.

## Parcours livré

Avec une mission v2 active autorisant `http.discover` et `http.check_redirect` :

```bash
python -m argos web run --mission-id UUID --public-key reviewer.pub.pem --json
python -m argos web report --run-id UUID --json
python -m argos web retest --check-id UUID_CHECK_INITIAL --public-key reviewer.pub.pem --json
```

`run` et `resume` enchaînent automatiquement découverte puis vérification si
la capacité signée est présente, sauf arrêt ou panne d'isolation. Ils ne
sollicitent pas une confirmation entre les actions admises. `web check --run-id`
permet aussi de vérifier une découverte sauvegardée. Une seconde invocation de
`check` ne renvoie pas les mêmes sondes : les candidats déjà planifiés sont
conservés, y compris ceux dont le résultat est incertain.

`retest` crée explicitement trois nouveaux échanges et deux nouveaux marqueurs,
liés au check initial. Il ne rejoue aucun ancien ticket, ne remet pas à zéro les
quotas et ne redécouvre pas le site. Il peut détecter une régression après un
ancien contrôle négatif ou poursuivre explicitement après une tentative incertaine.
Un run arrêté/interrompu ne recommence pas ses sondes par `check` : il faut un
recontrôle explicite. Une mission expirée, révoquée ou sans la capacité reste refusée.

Les chemins `--db`, `--slirp`, `--slirp-library`, `--ca-bundle`, le provisionnement
de la clé publique et les codes de sortie sont ceux de [W3.1](WEB_CLI_DISCOVERY.md).
Un constat positif n'est pas un code d'erreur : les codes indiquent l'achèvement,
la couverture partielle ou l'échec technique, pas un seuil de sévérité.

## Sélection sans réponse attendue fournie à Argos

Le vérificateur sélectionne une route de page visitée par la découverte, avec
un parent enregistré et un paramètre à valeur de forme URL (`/chemin`,
`//hôte/chemin`, `http://...` ou `https://...`). Le nom du paramètre n'est pas
supposé connu : aucun catalogue `next/url/redirect` ne donne la réponse.

L'admission vérifie la preuve de lecture de cette route et celle de son parent,
ainsi que la présence du lien dans la capture du parent. Une URL de départ
contenant une query, mais jamais découverte dans une page/réponse, ne suffit pas
à fabriquer une provenance. Les contrôles de chemin manquant, routes bloquées
et clés dupliquées sont exclus de cette tranche. Les valeurs relatives sans
slash, paramètres imbriqués/doublement encodés et redirections DOM/JavaScript
restent hors de cette première capacité.

Une mutation remplace uniquement la valeur du champ sélectionné. L'ordre et
l'encodage des autres champs restent inchangés, notamment les jetons privés.
L'index du champ, son empreinte et les références de route sont conservés ; les
sorties ordinaires ne publient pas le nom arbitraire ou la valeur du paramètre.

Au plus 20 candidats nouveaux sont vérifiés par invocation. Une limite atteinte
rend la couverture partielle ; les candidats suivants ne sont pas exécutés
silencieusement. Au plus 200 enregistrements de check/recontrôle sont conservés
par run. Les URL planifiées des sondes comptent aussi contre `max_urls` et
`query_variants` signés, même si une tentative précédente n'a pas abouti.

## Oracle v1

Pour un candidat :

1. Exécuter la référence, avec l'URL découverte, sous `http.check_redirect`.
2. Remplacer la valeur sélectionnée par `https://redirect-proof.invalid/NONCE_1`.
3. Recommencer avec un nonce distinct généré par le runtime.

Chaque échange possède son propre identifiant, ticket, résolution, profil et
preuve. La méthode reste GET, sans cookies ou authentification transmis. Aucune
sonde ne devient une entrée de la frontière de découverte et aucune Location
n'est suivie, même incluse. Le nom du marqueur n'est jamais remis au résolveur
ou utilisé comme destination TCP par Argos : il reste une valeur de query vers
l'application incluse. Ce lot ne contrôle pas les actions internes du serveur cible.

`confirmed` exige trois preuves HTTP complètes, une référence accessible
(2xx/3xx admissible) et, pour **chacun** des deux marqueurs, un statut
301/302/303/307/308 avec une seule Location exactement égale au marqueur attendu.
Les marqueurs doivent différer. La concordance est stricte : un suffixe,
une query ou un fragment supplémentaire ne suffisent pas.

- HTTP 200 ou reflet du marqueur dans le corps : aucune confirmation.
- Un seul marqueur concordant : aucune confirmation.
- Refus explicite 400/422 des valeurs externes, ou navigation conservée locale,
  avec les trois échanges complets : `not_confirmed` pour ces essais.
- Login détecté, 401/403/407, 404/410 masquant la route, 429/503, erreur serveur,
  Location ambiguë, erreur TLS, réponse partielle, annulation, budget insuffisant
  ou preuve manquante : `inconclusive`, jamais une correction annoncée.

La détection de login utilise les observations HTML bornées de W3.1 et les
chemins usuels de redirection d'authentification ; elle ne connaît pas tous les
mécanismes d'identité. `not_confirmed` / `not_reproduced` signifie que ce
protocole n'a pas reproduit le comportement, pas que l'application est sûre
ou définitivement corrigée. L'absence de candidat donne `not_tested`.

## Preuves, intégrité et confidentialité

Le plan privé versionné `open-redirect-v1` lie run, route, paramètre, sources de
découverte, configuration signée, propriétaire, trois requêtes et marqueurs.
Le worker ne choisit ni l'oracle, ni ses marqueurs, ni la conclusion.
L'entrée agent habituelle ne peut pas fournir d'ID de plan ou de réponse attendue.

La preuve HTTP ajoute seulement une observation autorisée : rôle, empreinte du
plan, marqueur synthétique attendu, concordance, nombre de Locations et classe
de réponse. Le marqueur observé n'est conservé que s'il correspond exactement
à celui qu'Argos a généré. Les autres Locations, corps, cookies et valeurs de
query originales restent absents des vues ordinaires. Les requêtes nécessaires
au travail et les plans restent dans la base privée en clair, comme en W2/W3.1.

Le dernier échange et la conclusion sont commis dans la même transaction que
preuve HTTP, couverture de transport, ticket consommé et audit. La conclusion
n'est pas acceptée depuis un booléen fourni par un modèle : l'oracle est
recalculé depuis les reçus vérifiés lors de la lecture. Les liaisons des étapes,
marqueurs, plans, sources et observations sont contrôlées par empreintes.
Une faute d'écriture après réception ne laisse pas de constat confirmé orphelin.
Ces empreintes locales ne protègent pas contre un administrateur capable de
réécrire toute la base et ses empreintes.

Un crash interrompt la tentative et la vérification sans nouvelle requête.
`stop`, Ctrl+C, révocation et expiration gardent les contrôles existants avant
DNS, pendant le worker et dans la transaction terminale. Une sonde déjà reçue
par le serveur peut avoir eu un effet ; le runtime conserve cette incertitude.

## Historique et restitution

`redirect_checks` expose les étapes, états, marqueurs synthétiques et empreintes
des trois reçus. `findings` rassemble les comportements confirmés et leur
recontrôle, sans CVSS ou sévérité élevée automatique.

- `confirmed_findings` compte les constats confirmés qui ne sont pas actuellement
  marqués `not_reproduced`.
- `historical_confirmed_findings` conserve le nombre de constats ayant eu une
  confirmation, même après un recontrôle négatif.
- Un recontrôle négatif donne `not_reproduced`, sans effacer les anciennes preuves.
- Un recontrôle incertain donne `retest_inconclusive` ; le risque historique
  n'est pas déclaré résolu et reste dans `confirmed_findings`.
- Un recontrôle positif après un premier contrôle négatif crée aussi le constat.

La couverture de transport `executed` reste distincte de la vérification de
cette capacité ; tous les autres parcours/familles ne deviennent pas « vérifiés ».
La liste des contrôles est bornée et le rapport expose les lacunes et raisons.

## Qualification et suite

26 tests supplémentaires couvrent témoins positifs/négatifs, mutations bornées,
concordance des deux marqueurs, recontrôle et régression, budget épuisé entre
sondes, arrêt, altération de plans/reçus et rollback avant constat confirmé.
Deux tests hôte lancent le CLI réel et le worker isolé sur une application
locale : route aléatoire découverte, confirmation, correction puis recontrôle ;
processus tué pendant une sonde, récupération sans confirmation ni renvoi.
**711 tests passent sous Python 3.12 et 3.14**, dont 666 tests réguliers et
45 tests hôte activés explicitement. Ruff, formatage et Pyright passent aussi ;
le contrôle hors ligne du manifest W1.2 reste valide.

Tous les appels HTTP restent vers l’IP de la cible locale ; les marqueurs ne
sont ni résolus ni contactés par Argos. Le corpus W1.2 n'est pas évalué par ce lot.

**Suite : [W4.1 livré](WEB_BROWSER_WORKER.md)**, socle navigateur anonyme
confiné qualifié sur fixtures. W4.2 doit le raccorder aux missions signées,
tickets et preuves persistantes pour la découverte SPA/API depuis le CLI. Garder le transport HTTP déterministe et ce premier oracle
comme référence ; comptes et comparaisons d'identités resteront des extensions.
L'agent LLM et les autres familles de tests restent au plan W5–W7.
