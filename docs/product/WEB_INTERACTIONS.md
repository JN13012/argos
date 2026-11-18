# W4.3 — Interactions, redirections et sessions web

Préparation et livraison du 18 novembre 2026. **W4.3a livré et validé
localement ; W4.3b/c non implémentés**. Dépendances : [HTTP durable](WEB_HTTP_RUNTIME.md),
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
