# P1.4.2 — Réseau de mission et intégration ATTACK

Livré et qualifié localement le 16 novembre 2026, sous Linux/WSL amd64.
Le prochain lot est P1.5 : qualification Nmap en labo autorisé et revue ciblée.

## Chemin d'exécution

`ExecutionManager` choisit désormais `NetworkWorker` par défaut. Une dépendance
absente refuse la soumission avant sa mise en file ; aucun échec de préparation
ne déclenche une exécution sur le réseau de l'hôte. `local_processes=True`
conserve le superviseur historique pour les tests et les usages administrateur
explicites. Ce réglage ne doit pas être exposé comme paramètre d'une mission ou
d'un outil d'agent. Les anciens tests de processus l'utilisent explicitement.
Une demande déjà liée à un profil isolé ne peut pas reprendre dans ce mode local.

```text
Mission signée et plan borné
  → vérification de la cible et de l'action
  → profil versionné et demande persistés ensemble
  → worker systemd avec quotas contrôlés
  → namespace utilisateur/réseau externe, pare-feu nftables à refus par défaut
  → connexion rootless slirp4netns avec DNS intégré désactivé
  → outil dans un namespace utilisateur enfant, capabilities supprimées
  → sortie brute, observations et profil liés au reçu terminal
```

Le pare-feu est installé **avant** la création de l'interface TAP et relu dans
le noyau. Les chaînes d'entrée, sortie et transit ont une politique `drop`.
Seuls la destination littérale et les ports TCP du plan sont autorisés en
sortie, plus les échanges de voisinage IPv6 nécessaires au réseau privé.
Les réponses des connexions établies sont acceptées. UDP et les nouvelles
connexions TCP hors périmètre restent interdits.

Le namespace réseau appartient à un user namespace ancêtre de celui de
l'outil. L'outil ne dispose pas du droit de modifier ce pare-feu, de créer un
nouveau user namespace ou d'accéder à l'entrée de contrôle de l'ancre réseau.
Il voit les mêmes montages minimaux en lecture seule et quotas que le
[worker sans réseau](WORKER_ISOLATION.md). Le proxy userspace est une dépendance
de confiance de cette barrière, pas un outil piloté par le modèle.

Les processus réseau appartiennent au cgroup du job. Le gardien surveille
l'ancre et le proxy ; une disparition pendant l'exécution arrête l'outil.
Le pipe de vie, le namespace PID et `KillMode=control-group` couvrent la mort
du runtime, y compris les descendants détachés. Les échéances et l'annulation
du runtime restent actives pendant la préparation réseau. Le mandat est
revérifié avant lancement puis environ toutes les 250 ms et avant validation
du résultat ; aucune garantie de révocation à latence nulle n'est annoncée.

## Adresses et sorties

`NetworkPolicy` accepte une IP canonique et 1–32 ports TCP triés et uniques.
Le réseau technique utilise `10.253.0.0/24` et `fd00::/64`. Les cibles qui
entrent en conflit avec ces plages, les adresses link-local, les adresses
IPv4 mappées en IPv6, les zones IPv6 et les destinations ambiguës sont refusées.
Les boucles locales autres que `127.0.0.1` et `::1` sont également refusées.

Les deux boucles locales autorisées représentent l'hôte du runtime :

| Cible de mission | Adresse utilisée dans le namespace |
| --- | --- |
| `127.0.0.1` | `10.253.0.2`, proxy vers la boucle locale IPv4 de l'hôte |
| `::1` | `fd00::2`, proxy vers la boucle locale IPv6 de l'hôte |
| Autre IP prise en charge | Identique à la cible de mission |

Les arguments exécutés et le XML brut conservent l'adresse technique. Les
observations et ports sont explicitement rattachés à la cible logique après
analyse de ce XML ; le profil décrit la traduction. Aucune sortie brute n'est
réécrite. Les options Nmap ajoutent `--unprivileged` et `-6` pour une cible IPv6.
Le mode TCP connect est conservé ; aucun scan raw, NSE ou balayage CIDR n'est ajouté.

## Profil et preuves

Le profil `argos-network-v1` contient les identifiants de job et de mission,
la cible logique, l'adresse de connexion, les ports, les limites, les arguments
et les empreintes du programme, du helper, de libslirp, des règles et du code
de l'adaptateur et des gardiens. Ce profil décrit le lancement prévu ; un échec de préparation
n'atteste pas que l'outil a démarré. Il est enregistré dans
`pentest_job_isolation` avec son SHA-256 ;
son empreinte est aussi portée par l'enveloppe du plan persistant.

La finalisation associe le profil au reçu de preuve dans la même transaction
que l'état terminal et l'audit. Les lectures vérifient cette liaison : profil
manquant, modifié, non scellé ou reçu discordant sont refusés. Un échec de cette
écriture annule aussi les preuves et la transition terminale. Une reprise en
attente refuse un changement de profil, de dépendances, de code ou de limites.
Les demandes historiques sans profil peuvent être reprises avec un profil
nouveau après revalidation du mandat et décision de reprise enregistrée.

Ces empreintes ne sont pas des signatures : un acteur qui réécrit l'ensemble
de la base peut modifier les contenus et leurs empreintes. Les lectures de
compatibilité ne constituent pas une attestation externe de l'isolation.

## Dépendances qualifiées

Pas d'installation système ni de changement permanent des routes ou du
pare-feu hôte. Les règles existent uniquement dans les namespaces éphémères.
Deux paquets Ubuntu ont été téléchargés et extraits sous `/tmp/argos-network-tools`.
Les sommes ont été comparées aux métadonnées APT disponibles sur cet hôte.

| Paquet Ubuntu amd64 | Version | SHA-256 du `.deb` |
| --- | --- | --- |
| slirp4netns | 1.3.3-1 | `dda3ca5101c58e9585bfd6e7b9d26831090327120cfb5092172ead355f968dd4` |
| libslirp0 | 4.9.1-1ubuntu1.1 | `bfc8e5afed3287ecd28675fd683913e6b3c9d73bd16a63bc8f45cc3b7e6f83fb` |

Le helper déclare le commit `944fa94090e1fd1312232cbc0e6b43585553d824`,
libslirp 4.9.1 et libseccomp 2.6.0. Les notices des paquets indiquent notamment
GPL-2/GPL-2+ pour slirp4netns et BSD-3-clause pour libslirp, avec des notices
propres à certains fichiers. Aucun code tiers ni binaire n'est copié dans le
dépôt ; ces exécutables sont appelés comme dépendances externes. Leur revue
de sécurité et les conditions de distribution restent à intégrer à la bêta.

Environnement : Ubuntu 26.04.1 LTS, noyau WSL2 `6.18.58.1`, systemd 259.5,
bubblewrap 0.11.1, iproute2 6.19.0 et Python système 3.14.4 pour les gardiens.
Nmap 7.98 est présent mais aucun scan Nmap réel n'est exécuté dans ce lot.

Pour reproduire la préparation temporaire sur cet environnement précis :

```sh
mkdir -p /tmp/argos-network-tools
cd /tmp
apt-get download slirp4netns=1.3.3-1 libslirp0=4.9.1-1ubuntu1.1
sha256sum -c <<'HASHES'
dda3ca5101c58e9585bfd6e7b9d26831090327120cfb5092172ead355f968dd4  slirp4netns_1.3.3-1_amd64.deb
bfc8e5afed3287ecd28675fd683913e6b3c9d73bd16a63bc8f45cc3b7e6f83fb  libslirp0_4.9.1-1ubuntu1.1_amd64.deb
HASHES
dpkg-deb -x slirp4netns_1.3.3-1_amd64.deb /tmp/argos-network-tools
dpkg-deb -x libslirp0_4.9.1-1ubuntu1.1_amd64.deb /tmp/argos-network-tools
```

La qualification utilise ces chemins via les variables de test ci-dessous.
Le produit ne les lit pas implicitement : un administrateur fournit les chemins
avec `NetworkTools(slirp=..., library=...)` et passe son `NetworkWorker` au
gestionnaire. Sans configuration explicite, les chemins par défaut sont
`/usr/bin/slirp4netns` et `/usr/lib/x86_64-linux-gnu/libslirp.so.0`. Sur cet hôte,
ils ne sont pas installés globalement : une soumission utilisant ces chemins
absents échoue, elle ne bascule pas en mode local.

## Validation exécutée

```sh
ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1 \
ARGOS_SLIRP_PATH=/tmp/argos-network-tools/usr/bin/slirp4netns \
ARGOS_SLIRP_LIBRARY=/tmp/argos-network-tools/usr/lib/x86_64-linux-gnu/libslirp.so.0 \
.venv/bin/python -m pytest -q -o faulthandler_timeout=10
```

**311 réussites sous Python 3.14.6 et 311 sous Python 3.12.15.** Sans les
qualifications d'hôte : **288 réussites et 23 ignorés**. Ruff, formatage global
et Pyright passent. La CI distante n'a pas été exécutée ; les opt-ins de
qualification ne sont pas activés par son workflow courant.

Les 23 essais d'hôte comprennent dix essais du worker sans réseau et treize
du réseau de mission. Ils vérifient les ports autorisés IPv4/IPv6, une adresse
IPv4 non loopback de l'hôte, les témoins hors port/adresse/famille, le refus UDP
et DNS, le refus de modifier le pare-feu, les contrôles de mandat, les profils
et reçus persistants, les refus de reprise modifiée, un helper qui refuse de
démarrer et le nettoyage complet après la mort du runtime. Les tests unitaires
vérifient aussi la suppression ou modification du profil, la liaison au reçu
et le rollback d'une écriture de profil ou de scellement refusée.

Le moteur est exercé avec un runner synthétique qui conserve les vraies
vérifications de mission signée et n'ouvre qu'une connexion vers le serveur
local du test. Il produit ensuite du XML de forme Nmap. Cela qualifie le
transport, l'intégration et la provenance, pas les performances du véritable
Nmap ni sa compatibilité complète avec les montages du worker.

## Suite P1.5 et limites

- Qualifier Nmap réel, ses fichiers de données et la reconnaissance en deux
  phases dans un labo explicitement autorisé ; mesurer omissions et limites.
- Revoir indépendamment les courses annulation/révocation/fin et les scénarios
  de saturation, crash, reprise et panne de proxy ; préparer un runner CI adapté.
- Tester les environnements de déploiement visés, les routes IPv6 externes et
  les versions de dépendances ; les preuves actuelles restent locales à cet hôte.
- Le proxy userspace fait partie de la barrière de confiance. Les services
  d'une cible autorisée peuvent eux-mêmes relayer des requêtes : le filtrage IP
  ne remplace pas les permissions applicatives ni la méthodologie de mission.
- Les runners synchrones historiques et le mode administrateur local explicite
  ne fournissent pas cette isolation. Ils ne sont pas des backends à exposer
  à l'agent. Aucun endpoint métier ni agent n'est ajouté par ce lot.

Sources techniques : [slirp4netns](https://github.com/rootless-containers/slirp4netns),
[manuel du helper](https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md),
[nftables](https://netfilter.org/projects/nftables/manpage.html),
[options Nmap IPv6 et privilèges](https://nmap.org/book/man-misc-options.html).
