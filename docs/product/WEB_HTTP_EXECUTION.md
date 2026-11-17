# W1.3 — Première tranche HTTP et CLI

Statut : **W3.2 livré et validé localement**, navigateur anonyme W4.1 à préparer.
Voir les [contrats W2.1](WEB_HTTP_POLICY.md) et le [transport W2.2](WEB_HTTP_TRANSPORT.md).
Le [runtime HTTP persistant](WEB_HTTP_RUNTIME.md) et le [CLI/découverte](WEB_CLI_DISCOVERY.md) sont livrés ; [le premier oracle W3.2 et son recontrôle](WEB_OPEN_REDIRECT.md) aussi. Boucle agent et autres familles restent à construire. Suite du [plan web](WEB_PENTEST_PLAN.md).

## Résultat attendu de W2/W3

Depuis une URL de client, sans compte ni documentation : exécuter des requêtes
HTTP contrôlées, découvrir des liens/formulaires/paramètres, conserver les
observations et vérifier un premier comportement vulnérable avec son témoin
corrigé. Produire un rapport partiel honnête et permettre arrêt/reprise.

La première capacité de validation est la **redirection ouverte** : prouver
que l'application redirige vers une destination externe contrôlée par le
paramètre testé, sans contacter cette destination. Cela donne un défaut
reproductible en boîte noire sans compte. Cela ne prouve ni vol de compte,
ni XSS, ni impact métier élevé. La couverture plus large reste W4–W7.

## Décisions techniques

- Premier transport : client HTTP/1.1 dédié, de confiance, en Python système
  avec bibliothèque standard `socket` et `ssl`, et lecteur HTTP borné dédié. Pas de dépendance
  ajoutée pour cette tranche ; pas de client générique accessible au modèle.
- Le runtime valide la mission et résout le nom ; le worker reçoit une seule
  IP vérifiée et un port, l'origine logique et la requête canonique. Il ne fait
  aucune résolution DNS et ne suit pas lui-même les redirections.
- Réutiliser l'isolation rootless, le filtrage IP/port, les quotas, le canal de
  vie et le nettoyage de `NetworkWorker`. Ne pas exécuter HTTP sur le réseau
  hôte comme solution de repli en cas de dépendance manquante.
- `http.client` doit recevoir une connexion explicitement attachée à l'IP,
  avec identité HTTP/TLS issue de l'origine logique. Un simple remplacement
  du nom dans l'URL ne suffit pas. Les essais doivent prouver destination TCP,
  Host, SNI et vérification de certificat avant de considérer cela livré.
- Une requête, une connexion, un worker ; pas de pool, HTTP/2, HTTP/3, proxy
  hérité, cookies persistants, authentification, upgrade ou décompression
  automatique dans cette tranche. Les valeurs reçues restent des données.

Le filtrage réseau IP/port ne sépare pas deux sites d'un CDN. Ici, la frontière
applicative est le worker HTTP fixe : le planificateur ne contrôle ni socket,
ni Host, ni script. Ce montage ne confine pas encore un navigateur ou un outil
arbitraire. W4 devra une passerelle applicative qualifiée sans egress direct,
avec contrôle des origines et chemins ; un tunnel CONNECT seul ne vérifie pas
les chemins HTTP sous TLS. Ne pas déclarer cette partie implémentée par W2.

## Interfaces à coder

Les contrats W2.1 sont maintenant implémentés ; leurs limites effectives
sont documentées dans [WEB_HTTP_POLICY.md](WEB_HTTP_POLICY.md). Les éléments
de transport, preuve durable et runtime ci-dessous restent des exigences.
Les structures sont immuables, typées, versionnées et refusent les champs
inconnus. Les identifiants sont attribués par le runtime ; aucun appelant ne
fournit un booléen d'autorisation, une IP résolue ou un profil de confinement.

| Contrat | Données et contraintes |
| --- | --- |
| WebRequest | mission_id, request_id, parent_request_id facultatif, capability_id, URL canonique, méthode GET ou HEAD, identité anonyme, objectif et empreinte de configuration ; pas de corps ni de headers libres |
| PreparedWebRequest | Résultat privé de la politique : requête, origine, IP choisie, port, Host, nom TLS, ticket de budget, deadline et profil de worker vérifié ; non constructible à partir du JSON agent |
| WebResponse | request_id, statut HTTP, headers en liste ordonnée préservant les doublons, IP de connexion, identité TLS, dates UTC, durées monotones, compteurs, complétude du corps et référence de preuve |
| WebFailure | request_id, code stable, phase, compteurs et référence de preuve éventuelle ; jamais une exception brute contenant URL/secret ou une pseudo-réponse HTTP |
| WebEvidence | Identité mission/requête, empreintes configuration/profil, décision, réponse ou erreur, données expurgées, politique d'expurgation et hash canonique ; format distinct du XML Nmap |
| WebCoverage | capability_id, route_id, identité, applicable/prérequis, état et raison, références d'observations/preuves ; ne porte pas à elle seule une vulnérabilité confirmée |

Un HTTP 403/404/429/500 est une réponse, pas une panne de transport ni une
preuve universelle de faille. Un refus de périmètre est un échec de politique,
avec `request_sent=false`. Un corps tronqué ne devient jamais une réponse
complète ou une preuve d'absence de vulnérabilité.

Codes initiaux : `mission_inactive`, `approval_invalid`, `scope_denied`,
`effect_denied`, `dns_failed`, `dns_denied`, `dns_timeout`, `tls_failed`,
`connect_failed`, `protocol_failed`, `request_timeout`, `response_limit`,
`budget_exhausted`, `cancelled`, `interrupted`, `isolation_unavailable`,
`evidence_failed`. Les erreurs non transitoires ne provoquent pas de retry caché.

## Chaîne d'exécution obligatoire

1. Recharger la mission via `MissionStore.get_reviewed`, vérifier la
   configuration signée exacte et l'action `web_http_request`. Ne pas assouplir
   la politique IP actuelle pour accepter un nom de domaine arbitraire.
2. Canonicaliser l'URL avec W1.1, vérifier origine, exclusions et effets de la
   capacité. Une URL découverte hors périmètre devient un candidat sans appel.
3. Réserver atomiquement un ticket de requête, un créneau global/par origine
   et la capacité de preuve dans la base. Attente et DNS comptent dans la durée
   de mission ; un ticket ne permet pas plusieurs connexions physiques.
4. Résoudre dans le runtime avec le résolveur système administré, sous délai
   et supervision annulable. Les littéraux ne déclenchent pas de DNS. Aucun
   résolveur, proxy ou fichier hosts n'est fourni par le modèle. Borner à 16
   adresses ; un ensemble vide, trop grand ou contenant une IP interdite est
   refusé intégralement. Refuser privés, loopback, link-local, multicast,
   réservés, IPv4-mapped et préfixes techniques du worker dans le profil externe.
5. Choisir de manière déterministe une adresse admissible, journaliser
   résolution/décision, épingler cette IP. Une nouvelle connexion exige un
   nouveau ticket, une revalidation et une nouvelle résolution ; pas de course
   entre validation DNS et résolution interne au client. Pas de fallback
   automatique vers une autre IP en cas de panne dans la première tranche.
6. Revalider mission et budget juste avant lancement. Construire le profil
   réseau limité à cette IP et ce port ; lancer le worker HTTP avec les quotas.
7. Le worker construit la requête canonique, fixe Host et la connexion TCP.
   Sous HTTPS, vérifier chaîne et identité du certificat avec CA explicitement
   montée en lecture seule ; SNI correspond au nom DNS logique. Pour un littéral,
   vérifier l'identité IP ; ne pas inventer un nom SNI. Aucun `verify=false`,
   repli HTTP ou chargement de CA par variable d'environnement.
8. Lire en flux sous deadline, plafonner les headers, le corps et le protocole,
   arrêter sur annulation/révocation/expiration ; conserver le résultat partiel.
9. Expurger, valider la preuve puis commettre résultat, preuve et audit ensemble.
   Aucun constat confirmé n'est produit si la preuve manque ou échoue.

Le résolveur est une fonction de confiance du runtime, hors worker ; son appel
bloquant doit pouvoir être interrompu par supervision de processus. Une simple
limite appliquée à une attente de thread ne suffit pas à arrêter le résolveur.
Une résolution supervisée doit terminer sous 5 secondes et dans la durée restante.
Le trafic DNS du runtime reste distinct du trafic HTTP des workers ; ce lot ne
promet pas que le résolveur système est isolé par leur firewall.

## Redirections, effets et TLS

Le worker renvoie 301/302/303/307/308 et Location sans les suivre. Le runtime
résout les Locations relatives, vérifie la destination complète et crée une
nouvelle requête/ticket pour chaque saut. Maximum cinq sauts, cycles détectés,
aucun transfert d'Authorization/Cookie. Les destinations exclues ne déclenchent
ni DNS ni connexion ; elles restent des observations. Les downgrade HTTPS→HTTP
ne sont pas suivis automatiquement, même si HTTP est aussi inclus.

Le mode découverte suit seulement les sauts inclus. La capacité de preuve de
redirection ouverte désactive tout suivi, même inclus, pour vérifier Location.
Meta-refresh, JavaScript, formulaires et URLs extraites sont des candidats,
jamais des instructions à exécuter depuis une réponse.

GET/HEAD sont une restriction de la tranche initiale, pas une garantie d'absence
d'effet serveur. Les routes identifiées comme déconnexion, suppression, action
métier ou déclenchement externe sont exclues de l'exploration automatique.
Les cas ambigus sont bloqués et signalés. POST, inscription et écritures
restent pour des capacités dédiées avec permissions d'effets déjà disponibles
dans la configuration. Activer `allow_test_writes` ne donne pas un POST libre.

Les erreurs TLS deviennent des observations techniques et une couverture bloquée,
sans continuer en clair ou ignorer le certificat. Les essais TLS ultérieurs
pourront constituer une capacité distincte et ne désactiveront pas implicitement
la validation du transport ordinaire.

## Budgets, framing et confinement à adapter

| Budget additionnel pour W2/W3 | Valeur initiale proposée | Traitement |
| --- | --- | --- |
| DNS par tentative | 5 s, au plus 16 adresses | Dans deadline restante ; refus si dépassement |
| Headers de réponse | 32 KiB, 100 champs, ligne 8 KiB | Lecture bornée avant accumulation ; erreur protocole/limite |
| Redirections | 5 sauts | Un ticket par saut ; arrêt explicite |
| Retries automatiques | 0 | Aucune répétition cachée d'une requête incertaine |
| Réponses 429/503 | Arrêt des nouvelles requêtes sur l'origine | Retry-After interprété ; attente au plus 60 s, au-delà origine suspendue sans reprise anticipée ; sans valeur valide, pause 5 s ; pas de contournement par une autre IP |
| URLs uniques | 1000 | Frontière bornée ; reste indiqué non exploré |
| Profondeur de découverte | 5 | Graine profondeur 0 ; au-delà non exploré |
| Variantes de query par route | 10 | Déduplication sans effacer les différences d'identité |
| Volume total de preuves par mission | 64 MiB | Réservation persistante avant requête, arrêt avant dépassement |
| Taille d'une URL | 8 KiB | Refus avant DNS |

Ces budgets n'existent pas dans W1.1 : ils doivent être ajoutés, validés et liés
à la signature avant exécution, sans retoucher silencieusement une configuration
déjà approuvée. Un format v2 sera introduit pour les missions exécutables ;
les brouillons v1 restent lisibles, sans autorisation HTTP implicite ni upgrade
d'une mission active. Le chargement v2 et les limites du worker sont livrés en W2.1/W2.2.
Les plafonds globaux W1.1 (temps, requêtes, débit, concurrence, réponse) restent
applicables ; la limite la plus restrictive prévaut. La concurrence est globale
à la mission et bornée aussi par origine ; elle ne multiplie pas le débit.
La v2 lie aussi la liste des capacités HTTP permises à la signature : première
liste fermée `http.discover` et `http.check_redirect`, sans code ni paramètres
de transport libres. Les profils anonymes n'utilisent pas les références de
comptes W1.1 ; leur présence ne doit pas injecter des secrets dans cette tranche.
Le profil privé d'évaluation requis par W1.2 est distinct du profil externe :
réseaux de test explicitement inclus dans un contrat signé, conservation du
contrôle d'origine, des exclusions et de TLS. Il doit être défini avec les
contrats W2 puis qualifié avant les essais de transport privés ; aucun flag
sur une requête, nom de benchmark ou exception de test cachée ne le remplace.

Le worker actuel plafonne stdout à 2 MiB : l'output HTTP ne peut pas être un
JSON avec corps base64 de 2 MiB. Contrat IPC choisi : quatre octets big-endian
pour la taille de métadonnées, JSON UTF-8 borné à 64 KiB, puis corps binaire.
Les longueurs et l'empreinte du corps conservé sont contrôlées ; pas de suffixe
ou de donnée non annoncée. Le corps retenu effectif est :

```text
min(config.response_bytes, worker.output_bytes - 65536 - 4 - 1)
```

La marge d'un octet évite de toucher le plafond conservateur du worker. Si la
limite effective n'est pas positive, refuser avant lancement. Le profil et le
rapport conservent les limites demandée/effective. Demander 16 MiB en v1 ne
promet pas de les conserver avec le worker actuel. `Accept-Encoding: identity`
est imposé ; encodage compressé reçu malgré cela donne une réponse partielle
non décodée, avec limite explicite. Borner aussi les réponses intermédiaires,
les chunks et la durée totale ; ne pas se fier à Content-Length.

Le worker doit disposer de son script fixe, de son entrée privée et du bundle CA :

- Montage en lecture seule du seul worker HTTP versionné et du bundle CA
  administré, jamais de tout le checkout, du home ou de `/etc`.
- Entrée JSON bornée à 64 KiB par descripteur privé, distinct du canal de vie
  du guardian ; aucune URL, query ou valeur sensible dans argv/environnement.
- Aucun script, montage, header Host, destination IP ou chemin de CA fourni par
  l'agent. Identités/hashes du code et de la CA intégrés au profil vérifié.
- Entrée privée propagée explicitement à travers guardian/bubblewrap, FD
  superflus fermés. La perte du canal de vie garde son rôle d'arrêt.
- Essais de refus pour socket vers autre IP/port, DNS direct, montage additionnel,
  héritage HTTP_PROXY/HTTPS_PROXY/ALL_PROXY et lecture de fichiers évaluateur.

L'API actuelle de NetworkWorker suppose notamment une cible en dernier argument ;
il faut une entrée HTTP interne dédiée. Ne pas détourner le runner Nmap ni
exposer une méthode générique de montage ou d'exécution au modèle.

## Persistance, reprise et confidentialité

Les tables Nmap stockent des IP, plans de scan et XML : ne pas y placer de
pseudo-scan HTTP. Ajouter des tables HTTP versionnées pour demandes, tickets,
échanges, couverture et preuves dans la même base locale, en réutilisant le
cycle de mission, le verrou d'unique propriétaire du runtime et les invariants
de transaction. Une mission web ne gagne pas de scope IP persistant ni d'action
Nmap. Le plan doit relire la configuration signée avant chaque nouvelle action.

La politique HTTP dédiée est appelée seulement après vérification indépendante
du grant. Elle audite origine, chemin, effets et résolution avant le lancement.
Le refus HTTP actuel reste tant que ce chemin et son confinement ne sont pas
qualifiés ; une modification du seul enum ne lève aucun contrôle.

En terminal, ticket consommé, état, échange/preuve et audit sont commis dans
une transaction. Une panne de stockage arrête les actions et n'annonce pas
une réussite. Les jobs en vol deviennent `interrupted` après crash ; aucun
renvoi automatique, même pour GET. Les demandes encore non envoyées peuvent
reprendre explicitement après revalidation. Le résultat peut rester incertain
côté serveur ; une erreur locale ne signifie pas qu'il n'a rien reçu.

La révocation est contrôlée avant DNS, lancement et commit, et périodiquement
pendant le worker (cadence visée 250 ms, délai d'arrêt réel à mesurer). Une
annulation déjà observée avant le commit interdit un terminal réussi. Il n'existe
pas de garantie de zéro effet distant à l'instant exact de la révocation.

Les requêtes et preuves privées ne sont pas des logs : répertoire restreint
0700, fichiers 0600, accès par mission, rétention explicite. Les paramètres
originaux nécessaires à la reprise peuvent rester dans la base locale privée ;
ce stockage n'est pas chiffré par les mécanismes SQLite actuels. Aucun corps
sensible intégral n'est conservé par défaut dans les preuves ou envoyé au modèle.
Le corps est traité dans la zone privée bornée puis écarté ; seules observations
structurées nécessaires et preuves expurgées sont archivées.

Masquer Authorization, Cookie, Set-Cookie, valeurs de query, secrets reconnus,
chemins sensibles et données personnelles dans les vues ordinaires. Ne pas
prétendre qu'une regex expurge tout contenu arbitraire : les extraits de corps
exigent une liste d'informations explicitement conservables par capacité.
Pour le premier test, seules les destinations synthétiques et nonces générés
par Argos sont des valeurs réutilisables dans la preuve. Les données brutes ne
sont jamais envoyées à un LLM par défaut. Le hash canonique couvre la preuve
expurgée et sa version d'expurgation ; ce n'est pas une signature contre un
administrateur capable de réécrire toute la base.

## Premier test traversant : W2-OR-01

Cas de référence à réaliser en W2/W3, distinct des 12 défis sélectionnés W1.2.
Un petit témoin ciblé complète ces suites sans reconstruire leur catalogue.

- La page de départ expose un lien vers une route de navigation paramétrée,
  par exemple `/continue?next=/catalog`. Le chemin n'est pas donné à Argos :
  il le découvre et relève le paramètre depuis la page.
- Le test observe une réponse de référence, puis soumet deux destinations
  synthétiques distinctes `https://redirect-proof.invalid/<nonce>` via ce
  paramètre. Aucun service n'est déployé à cette adresse et aucun accès réseau
  n'y est fait ; cette chaîne sert uniquement de marqueur.
- Le cas vulnérable renvoie un statut de redirection HTTP et une Location
  correspondant à chaque marqueur. Une réflexion dans le corps, un HTTP 200,
  un seul header incomplet ou un simple lien externe ne confirment pas le défaut.
- Le témoin corrigé garde la navigation locale ou refuse la destination externe ;
  les mêmes essais ne confirment plus la redirection ouverte. Les soft-404 et
  redirections de login sont des cas distincts, pas des vulnérabilités par défaut.
- La preuve rassemble les trois échanges, la correspondance paramètre/Location,
  les nonces, la version de capacité et les raisons de conclusion. Le rapport
  confirme le comportement, qualifie l'impact observé et laisse l'impact métier
  à établir ; aucune sévérité élevée ou chaîne de compromission automatique.
- L'évaluateur connaît la version vulnérable/corrigée ; le planificateur ne
  reçoit ni réponse attendue ni instructions internes. Rejouer après correction.

La création de requêtes concerne uniquement l'application incluse, avec budgets
et politique d'effets. La valeur d'un paramètre n'est pas une nouvelle cible de
connexion. Cette propriété doit être prouvée par absence de DNS/connexion vers
le marqueur et par comparaison des deux versions.

## Ordre des changements et acceptation

| Tranche | Livrable | Vérification nécessaire |
| --- | --- | --- |
| W2.1 | Contrats HTTP, config v2, limites et politique hors ligne | Missions v1 inchangées ; v2 exacte et signée ; origine/exclusions/effets et réservations refusent les erreurs sans réseau |
| W2.2 | Résolveur supervisé et worker HTTP attaché à l'IP, IPC et TLS | Deux origines sur une IP restent distinctes ; DNS changeant/mixte refusé ; certificat et Host/SNI vérifiés ; egress et héritages refusés ; corps/headers/temps réellement bornés |
| W2.3 | Stockage HTTP, tickets, audit, expurgation et cycle du runtime | Rollback injecté, altération détectée, saturation, arrêt/révocation, crash/reprise et aucune répétition implicite |
| W3.1 | Commandes CLI et exploration HTTP déterministe | URL seule, liens/paramètres découverts, soft-404, login bloqué, redirections et couverture partielle affichée ; sortie JSON cohérente |
| W3.2 | W2-OR-01, rapport et recontrôle | Détection sur le cas vulnérable, rejet sur corrigé, preuves complètes ; aucune connexion au marqueur ; arrêt propre et résultats reproductibles |

W2.1 définit la réservation ; sa persistance et les compteurs interprocessus
sont qualifiés en W2.3 avant ouverture du CLI. W2.2 teste le transport sur des
cibles contrôlées ; ce n'est pas un chemin utilisateur contournant la mission.
Chaque tranche laisse les fonctionnalités actives non qualifiées inaccessibles.

W2.1 livré dans `backend/attack/web/` :

- [x] Ajouter les contrats de requête, résultat, erreur et couverture, sans I/O.
- [x] Ajouter la configuration exécutable v2, budgets et liste de capacités,
  avec sérialisation canonique et lecture v1 conservée sans activation implicite.
- [x] Définir les profils de destination externe et privé d'évaluation comme
  permissions signées distinctes, avec refus des réseaux non inclus.
- [x] Ajouter la politique HTTP et la préparation hors ligne : mission active,
  signature exacte, capacité, URL, effets et adresses fournies par le résolveur
  de confiance ; aucun résolveur ni drapeau de vérification dans l'entrée agent.
- [x] Tester URL hors scope avant DNS, origines sur IP commune, exclusions,
  Host/IP fournis par l'appelant, résolution mixte, limites invalides et v2 altérée.
- [x] Conserver les refus de l'exécuteur HTTP tant que W2.2/W2.3 sont absents ;
  vérifier les régressions Nmap et les exports du corpus W1.2.

Commit du lot : `feat(web): add HTTP contracts and policy`. Les tests de W2.1
ne doivent ouvrir aucune socket ; l'absence de transport n'est pas compensée
par un appel HTTPX direct dans le CLI ou dans les tests d'intégration produit.

Commandes `argos web init`, `plan`, `activate`, `run`, `status`, `stop`, `resume`
et `report` livrées en W3.1 ; `check` et `retest` sont livrées en W3.2. Un import Python n'autorise
pas un transport hôte alternatif. Réutiliser les services derrière le CLI pour
la future API. Les contrats d’erreurs, sorties et codes du CLI sont documentés dans
[W3.1](WEB_CLI_DISCOVERY.md), sans confondre découverte et pentest complet.

## Sources primaires et limites de cette spécification

Consultées le 16 novembre 2026 ; aucune dépendance nouvelle ni cible exécutée :

- [Python 3.12 — http.client](https://docs.python.org/3.12/library/http.client.html) : primitives HTTP/HTTPS et limites de leur interface ; le transport épinglé est une adaptation Argos à tester, pas une garantie fournie par ce module.
- [Python 3.12 — ssl](https://docs.python.org/3.12/library/ssl.html) : certificats et identité TLS ; le bundle administré et son montage restent à qualifier sur l'hôte cible.
- [HTTPX — variables d'environnement](https://www.python-httpx.org/environment_variables/) : environnement pris en compte par défaut ; le client déjà dépendance d'Argos ne constitue pas une isolation ni une connexion épinglée par défaut.
- [HTTPX — transports](https://www.python-httpx.org/advanced/transports/) : possibilité de transports personnalisés ; aucune nouvelle dépendance ou adoption n'est déduite de cette lecture.
- [RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110) : sémantique HTTP, redirections et Retry-After ; les budgets et politiques ci-dessus sont les choix Argos.

Le document est vérifié contre les contraintes actuelles du code. W2.2 livre
montages, framing et contrôles DNS/TLS ; W2.3 livre compteurs et preuves
persistées. CLI, découverte et oracles restent à implémenter et mesurer. La préparation W1 est terminée ; les cibles corrigées,
images et scores du corpus W1.2 restent à qualifier avec l'exécution.

## Bilan W2.1

- Config v2 canonique : capacités et budgets HTTP, profils externe/privé
  explicitement signés ; lecture et signatures v1 conservées sans upgrade.
- DTO immuables de requête, résolution interne, résultat, erreur, reçu et
  couverture ; entrée agent limitée à URL/méthode/capacité.
- Préflight et planification hors ligne adossés aux missions persistées,
  revalidation après DNS, refus du DNS mixte/hors profil/périmé et des effets
  identifiés. Demande de budget calculée, mais aucune réservation acquise.
- `PreparedWebRequest` est un plan interne partiel : IP/Host/TLS et limites,
  pas un ticket, une deadline d'exécution persistée ou un profil réseau signé
  entièrement construit. `transport_enabled` reste faux ; politique d'exécution
  HTTP toujours fermée. Le résolveur réel, les backoffs et l'audit de chaque
  tentative seront réalisés avec W2.2/W2.3.
- **548 tests passent sous Python 3.12 et 3.14**, dont 115 nouveaux tests W2.1
  sans socket/DNS et les 23 tests hôte activés explicitement pour les régressions.
  Ruff, formatage et Pyright propres ; exemples v1/v2 chargés et liens vérifiés.
- Aucun scan client, nouvelle dépendance ou service ajouté. L'expurgation réelle
  et la vérification des reçus de preuve ne sont pas livrées par les DTO.

**W2.2 livré** : voir le [bilan du transport](WEB_HTTP_TRANSPORT.md).
**W2.3 livré** : voir le [bilan du runtime](WEB_HTTP_RUNTIME.md).
**W3.1 livré** : voir le [bilan CLI/découverte](WEB_CLI_DISCOVERY.md).
**W3.2 livré** : voir le [bilan vérification/recontrôle](WEB_OPEN_REDIRECT.md).
Suite : W4.1, navigation anonyme confinée.
