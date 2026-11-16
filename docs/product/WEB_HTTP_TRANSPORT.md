# W2.2 — Transport HTTP isolé

Le résolveur supervisé et le worker HTTP interne sont implémentés. Les essais
réels utilisent uniquement des serveurs locaux possédés, avec le profil privé
v2 signé. La politique générale refuse toujours l'action HTTP : cette primitive
n'est exposée ni au CLI ni à un agent. W2.3 doit apporter tickets, compteurs,
preuves et cycle du runtime avant l’ouverture du parcours utilisateur.

## Chemin livré

1. `WebPolicy.preflight` vérifie hors ligne la mission signée, l'origine,
   les exclusions, les effets reconnus et un instantané de budget.
2. `WebResolver.resolve` lance le résolveur système dans un processus Python
   isolé de l'environnement applicatif par `-I`. Le parent borne l'attente à
   la plus petite deadline, au plus cinq secondes, surveille annulation et
   activité, puis tue et récolte le processus en cas d'arrêt. Une IP littérale
   ne lance aucun processus DNS. Sortie bornée à 4096 octets et 16 adresses.
3. `WebPolicy.prepare` relit la mission après DNS et refuse toute réponse
   contenant une adresse hors profil, même si d'autres adresses sont admises.
   Il conserve l'origine logique et choisit une seule IP déterministe.
4. La primitive interne `HTTPWorker.exchange` utilise ce plan et le callback
   d'activité du runtime. Le réseau rootless existant autorise seulement l'IP
   et le port choisis ; aucune résolution DNS n'existe dans le worker HTTP.
5. Le guardian vérifie les empreintes du script, du bundle CA et de l'entrée
   privée, puis lance exclusivement `/usr/bin/python3 -I /argos-http.py`.
   Bubblewrap monte le script fixe et le bundle CA en lecture seule. Aucun
   montage du checkout, du home ou de `/etc` n'est ajouté.
6. Une connexion TCP numérique réalise un seul GET ou HEAD HTTP/1.1, avec Host
   logique. HTTPS impose chaîne et identité du certificat, avec SNI DNS ;
   pour une identité IP, la bibliothèque TLS vérifie l'IP sans inventer de SNI.
   Aucune redirection, nouvelle tentative, compression, authentification,
   transmission de cookie, proxy ou connexion de secours n'est automatique.

Le résolveur utilise la configuration système administrée, sur le réseau du
runtime. Il n'est pas protégé par le firewall du worker. Le choix d'IP n'est
jamais refait pendant la connexion HTTP ; deux origines sur la même IP gardent
des Host/SNI distincts. La query UTF-8 est encodée pour la ligne HTTP sans
interpréter ses valeurs comme des destinations ou des instructions.

Le profil interne couvre configuration, identifiant de requête, IP/port,
quotas, limite effective du corps, règles réseau, helpers, script, CA et code
du runtime. Ce profil n'est pas encore un reçu durable signé ou vérifié en
base. La liaison au ticket et à la preuve reste W2.3.

## Entrées privées et arrêt

L'entrée JSON de 64 KiB maximum est préparée dans un fichier temporaire 0600,
absent des arguments et de l'environnement du worker. Le guardian exige un
fichier régulier appartenant à l'utilisateur, sans accès groupe/autres et sans
suivre un lien symbolique. Il vérifie son hash, ouvre le descripteur puis le
transmet comme stdin du seul enfant. Son propre stdin conserve le rôle de
canal de vie du runtime ; les deux canaux sont distincts. Le temporaire est
supprimé après terminaison, y compris en cas d'exception.

Le guardian, les namespaces, les cgroups et le filtrage réseau restent ceux
qualifiés par les tests du worker réseau. Le nouveau chemin n'accepte aucun
exécutable ni destination de montage fournis par une requête. Il n'existe pas
de repli sur un client HTTP lancé dans le processus hôte.

Le callback d'activité est contrôlé avant lancement, pendant l'attente
(cadence 250 ms) et après terminaison. L'annulation ferme le canal de vie et
arrête le groupe. L'essai HTTP attend qu'une requête ait effectivement atteint
le serveur, retire l'activité pendant l'attente de réponse et exige un retour
annulé en moins d'une seconde après observation par le callback. Cette borne
locale de test n'est pas un SLA universel de révocation ; le raccordement à la
mission persistée et l'arrêt après crash du runtime HTTP restent W2.3.

## Lecture et résultat

Le lecteur HTTP dédié utilise `socket` et `ssl`, avec une deadline totale
réappliquée à chaque lecture, écriture et handshake. Il n'utilise pas le lecteur
par défaut de `http.client` : les lignes et les en-têtes sont bornés avant
accumulation, y compris les réponses intermédiaires et les tailles de chunks.

- Au plus 32 KiB de headers, 100 champs par réponse et 8 KiB par ligne, selon
  les limites v2 éventuellement plus basses ; doublons conservés en ordre.
- Au plus cinq réponses informationnelles avant la réponse finale ; refus
  d'upgrade, headers repliés, contrôles, framing ambigu ou Content-Length double.
- Corps borné à `min(response_bytes, output_bytes - 65536 - 4 - 1)`, sans se
  fier au Content-Length annoncé. Chunks lus sous quota, compteur plafonné à
  65536. Extensions de chunks et trailers non vides refusés dans cette tranche.
- Compression reçue malgré `Accept-Encoding: identity` signalée comme partielle,
  sans décodage. Réponse trop volumineuse tronquée avec état explicite. Les
  octets déjà reçus du corps restent disponibles après timeout ou EOF prématuré.
- Sortie : longueur big-endian sur quatre octets, métadonnées JSON au plus
  64 KiB, corps brut. Taille et SHA-256 du corps vérifiés par le parent ; suffixe,
  troncature, hash invalide ou métadonnées incohérentes refusés.
- Si l'encodage JSON des headers dépasse le budget de métadonnées, ils sont
  retirés et le résultat devient partiel. Aucun résultat complet n'est inventé.

`HTTPExchange` est privé : statut, headers et corps bornés, état et code
technique. Il ne constitue ni preuve expurgée ni constat de vulnérabilité.
Un arrêt brutal du worker peut empêcher le retour d'une trame partielle : le
parent signale alors délai/isolation, sans inventer d'échange. Une panne locale
ne garantit pas que le serveur n'a reçu aucune requête. W2.3 devra conserver
cette incertitude et interdire le renvoi automatique.

## Validation

La suite ajoute 54 tests, dont 12 essais HTTP/TLS hôte activés explicitement.
Les tests réguliers couvrent protocole, framing altéré, limites, corps partiel,
entrée privée, empreintes, permissions et arrêt/récolte du processus DNS.
Les tests hôte vérifient Host avec deux noms sur la même IP, TLS/SNI, certificat
non fiable, identité DNS/IP incorrecte, absence de SNI pour un littéral IP,
proxies hérités ignorés, redirection non suivie, corps borné, deadline et arrêt
pendant une requête. Les tests réseau existants sont exécutés aussi : autre
IP/port, DNS direct, UDP et modification du firewall restent refusés.
Les montages HTTP fixes et refus d'entrée/exécutable supplémentaires sont
contrôlés séparément ; les essais HTTP réels de cette tranche utilisent IPv4.

**À la livraison W2.2, 602 tests passent sous Python 3.12 et 3.14**, dont 567 tests réguliers et
35 tests hôte activés, avec Ruff, formatage et Pyright propres. Le contrôle du
manifest de benchmarks passe aussi ; les 12 cas sélectionnés restent non exécutés.

Commandes de qualification de l’hôte de développement :

```bash
ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1 \
ARGOS_SLIRP_PATH=/tmp/argos-network-tools/usr/bin/slirp4netns \
ARGOS_SLIRP_LIBRARY=/tmp/argos-network-tools/usr/lib/x86_64-linux-gnu/libslirp.so.0 \
.venv/bin/python -m pytest -q -o faulthandler_timeout=10
```

Même suite avec `/tmp/argos-stabilization-py312/bin/python`. Ces helpers sont
provisionnés temporairement sur cet hôte ; ils ne sont pas installés par cette
étape. Un autre hôte doit provisionner ses dépendances, sinon le worker refuse.
Aucun service externe, cible client ou benchmark vulnérable n'est exécuté ici.

## Suite : W3.2

Le [runtime persistant W2.3](WEB_HTTP_RUNTIME.md) est livré : réservations avant
DNS, quotas, revalidation transactionnelle, redirections, pauses, preuves
expurgées et récupération sans renvoi. Ses 49 tests supplémentaires incluent
quatre essais hôte du worker HTTP réel. Le [CLI et la découverte W3.1](WEB_CLI_DISCOVERY.md)
sont livrés. Prochaine étape : preuve de redirection ouverte W3.2.
