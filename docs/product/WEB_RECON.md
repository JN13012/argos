# Reconnaissance Nmap → Gobuster → ffuf

Lot validé localement le 23 novembre 2026. Le pipeline CLI enchaîne Nmap,
découverte HTML et des scripts publics, Gobuster `dir`, ffuf sur chemins de fichiers, puis exploration
des liens nouvellement trouvés. Ce sont des observations, jamais des
vulnérabilités confirmées. La [décision d’intégration](../architecture/adr/0003-recon-tool-relay.md)
décrit le relais et ses limites.

## Utilisation

Créer la mission web avec `argos web init --config fichier.json`. Une cible de
laboratoire doit utiliser le profil signé `evaluation_private` et des réseaux
locaux explicites ; le profil public refuse les IP privées. Voir la
[configuration](WEB_CONFIG.md) et la
[signature hors ligne](WEB_CLI_DISCOVERY.md#préparer-le-grant-initial).
Le répertoire de base est privé, mode 0700 ; bases et approbations sont en 0600.

Si Nmap fait partie du mandat, créer aussi sa mission IP dans la même base :

```bash
python -m argos recon network-init --target-ip 127.0.0.1 --reference laboratoire-local
```

Faire revoir et signer séparément les deux missions par l’autorité hors ligne,
puis activer chaque UUID avec la commande `web activate` existante. Le CLI de
reconnaissance ne fabrique pas lui-même une approbation. Exemple d’exécution,
après activation, sur le port du serveur de laboratoire :

```bash
python -m argos recon run \
  --mission-id UUID_WEB --network-mission-id UUID_IP \
  --target-ip 127.0.0.1 --ports 8080 \
  --public-key /chemin/prive/reviewer.pub.pem \
  --wordlist /chemin/prive/directories.txt \
  --ffuf-wordlist /chemin/prive/files.txt
```

`--db` permet de choisir la base ; défaut `.argos/web/missions.sqlite3`.
`recon plan --mission-id UUID_WEB` est hors réseau.
`recon report --run-id UUID_RECON` relit le bilan JSON enregistré.
Le bilan contient l’UUID de découverte, utilisable avec les commandes existantes
`web report` et `web stop`. SIGINT/SIGTERM arrêtent l’exécution courante.
Codes de sortie : 0 terminé sur la liste bornée, 3 partiel, 130 signal reçu,
1 erreur d’exécution/stockage, 2 entrée ou autorisation invalide.

Sans mission IP explicite, Nmap est bloqué et le bilan global est partiel.
L’étape web reste utilisable. Une découverte ou un port ouvert n’élargit jamais
les autorisations. Une mission web déjà explorée ne peut pas être relancée
implicitement ; aucun replay automatique n’est ajouté.

## Contrats et options

| Option Nmap | Prise en charge actuelle |
| --- | --- |
| `-sT` | Oui, TCP connect imposé, avec `--unprivileged -Pn -n -T2` |
| `-sV` | Facultatif via `--identify-versions`, mandat `service_identification` requis ; `--version-light` |
| `-sS` | Non : pas de paquets raw/capabilities |
| `-sC` | Non : aucun NSE intégré |
| `-p-` | Non : 1–32 ports explicites avec `--ports` |
| `-O` | Non : détection OS non intégrée |
| `-sU` | Non : UDP interdit par ce worker |

Un seul IP littéral ; `-6` ajouté pour IPv6. Pas d’arguments libres. Nmap a une
échéance de 75 s et `--host-timeout 60s`, une seule tentative supplémentaire.
Gobuster/ffuf ont un thread, une limite worker de 120 s, un tmpfs privé, des
quotas cgroup et des sorties bornées. Le jeton et les listes sont transmis par
un descripteur privé, sans apparaître dans les arguments des processus.
Chaque wordlist accepte au plus 256
chemins relatifs et 32 Kio ; options, URL, paramètres et traversées refusés.
Les listes intégrées sont une sélection courte, pas un corpus exhaustif.
Le nombre de requêtes du relais est borné à la taille de liste + 4 ; les
budgets et le débit signés de la mission s’appliquent en plus à tous les GET.
Les réponses 404/403/3xx restent des observations, les réponses génériques et
les requêtes manquantes restent explicites dans la couverture partielle.

Les profils d’outil, empreintes des binaires/listes et sorties, codes de sortie,
états HTTP et références de preuves sont conservés dans la base privée. Les
sorties brutes des énumérateurs sont seulement hachées, pas archivées ; aucun
contenu HTTP, cookie ou secret n’est imprimé. Le XML brut Nmap et son reçu
restent dans le magasin de preuves privé existant. La remise HTTP lie le corps
et les en-têtes expurgés au reçu avant consommation par l’outil.

## Prérequis et limites

Linux avec namespaces utilisateur/réseau, systemd utilisateur, cgroups v2,
bubblewrap, nftables, iproute2, slirp4netns et libslirp. Aucun repli sans isolation.
Les chemins des deux dernières dépendances sont configurables avec `--slirp`
et `--slirp-library`, le bundle CA avec `--ca-bundle`. Les trois exécutables
système sont attendus sous `/usr/bin` ; aucun binaire n’est embarqué dans Git.

Versions exercées sur cet hôte Ubuntu/WSL amd64 : Nmap 7.98 (`7.98+dfsg-1`),
Gobuster 3.8.2 (`3.8.2-1`), ffuf 2.1.0-dev (`2.1.0-1ubuntu0.24.04.3`).
Notices des paquets installés : Nmap `nmap-GPL-2` avec dispositions propres ;
Gobuster Apache-2.0 ; ffuf MIT. Nmap dépend notamment de liblinear/BLAS, Lua,
OpenSSL, libpcap, libssh2, PCRE2 et zlib ; les outils Go utilisent leurs paquets
système. Voir `/usr/share/doc/{nmap,gobuster,ffuf}/copyright` sur cet hôte et les
références officielles [Nmap](https://nmap.org/book/man-briefoptions.html),
[Gobuster](https://github.com/OJ/gobuster), [ffuf](https://github.com/ffuf/ffuf).

Le correctif BLAS utilise l’architecture MULTIARCH du système, recrée uniquement
le lien d’alternative vers une bibliothèque sous `/usr` en lecture seule et
lie son empreinte au profil. Le XML accepte uniquement UTF-8 et la déclaration
vide exacte `<!DOCTYPE nmaprun>` ; entités, DTD externe et sous-ensemble refusés.
La portabilité ARM est contrôlée par tests simulés, pas qualifiée sur matériel.
Windows natif et macOS ne disposent pas du worker d’isolation nécessaire.

Cette tranche ne rend pas le navigateur, ne gère pas de sessions ni de comptes,
ne découvre pas les sous-domaines/vhosts et ne fuzz pas les paramètres ou corps.
Pas de scan externe ou de qualification de couverture universelle. Les étapes
sont séquentielles ; les quotas ne sont pas globaux entre plusieurs bases.

## Validation de consolidation

Les tests `test_recon.py`, `test_recon_network.py` et `test_nmap_parser.py`
couvrent contrats, preuves, vrais binaires, CLI complet, chemins exclus,
redirection hors origine, DNS mixte refusé, budget partagé, timeout/annulation,
réponse générique, reprise sans replay, BLAS et XML. Les suites existantes
couvrent aussi concurrence, révocation, DNS épinglé, HTTP/TLS et isolation hôte.
Le timeout hôte ou un `finished exit="error"` de Nmap refuse un succès ; le XML
borné reste consultable dans les preuves d’échec. La fermeture normale du CLI
retourne 0, distinct d’un signal reçu. La fin d’un énumérateur annule son ticket
HTTP encore actif. Les plafonds de requêtes et de frontière restent partagés.

| Vérification finale | Résultat |
| --- | --- |
| Suite complète Python 3.12.15, essais hôte activés | 1 107 réussis, 0 échec, 0 ignoré ; 589,93 s |
| Suite complète Python 3.14.6, essais hôte activés | 1 107 réussis, 0 échec, 0 ignoré ; 586,03 s |
| Pipeline CLI de la wheel, hors checkout, sur serveur local | 1 réussi, 0 échec, 0 ignoré ; 10,12 s |
| Ruff, formatage, Pyright et liens locaux | Validés ; aucune erreur de typage |
| Wheel et sdist hors ligne | Construits ; sources Python de la wheel comparées au dépôt |

Commandes : reprendre les variables d’environnement de la
[validation hôte W4.2a](WEB_BROWSER_RUNTIME.md#validation-w42a), puis :

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
.venv/bin/python -m pytest -xq -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -xq -o faulthandler_timeout=30
git diff --check
```

Les trois options `ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1
ARGOS_TEST_BROWSER=1` sont activées pour les suites finales, sans tests ignorés.
Les essais ciblés du pipeline comptent huit cas hôte, inclus dans chaque suite.
Pour le paquet : `UV_CACHE_DIR=/tmp/argos-uv-cache uv build --offline --wheel
--sdist --out-dir /tmp/argos-recon-dist`, puis rejouer
`test_recon_network.py::test_real_nmap_gobuster_ffuf_pipeline` depuis `/tmp`,
avec la wheel extraite en tête de `PYTHONPATH`. Les chemins `/tmp` désignent
les dépendances préparées sur cet hôte. Aucun scan externe, CI distante,
qualification native ARM/Windows/macOS ni taux de découverte client n’est déduit
de ces essais. Le frontend n’a pas été modifié.

## M2.1 — Découverte statique et SPA

La racine qui partage le HTML du contrôle aléatoire reste un shell observé,
pas un soft 404. Les scripts/modulepreloads déclarés et imports JS littéraux
passent par les tickets HTTP existants. Analyse MIME explicite, sans exécution,
limitée à 2 Mio et 256 références par réponse, capture de 64 Kio. Les lectures
GET explicites et certaines propriétés locales constantes sont candidates à
vérification ; routes client, paramètres et préfixes de templates restent
statiques. Pas de résolution générale des expressions JavaScript. OpenAPI JSON
v3/Swagger v2 : chemins GET littéraux, sans YAML ni résolution des `$ref`.

Les routes dédupliquées gardent jusqu’à huit origines HTML, JavaScript,
wordlist ou OpenAPI, liées aux reçus sources. Les références statiques et
exclues issues des scripts/spécifications occupent chacune au plus un quart
de la frontière signée ; les captures sources conservent les références dans
leur propre plafond. Les limites sont explicites et les métadonnées consomment
le budget de preuves. Une extraction statique n’est pas une réponse HTTP
vérifiée ; une réponse HTTP n’est pas une vulnérabilité.

Qualification Juice Shop locale sans liste d’endpoints fournie, avec les mêmes
plafonds qu’au passage initial (150 requêtes, 100 routes, profondeur 3) : 49
reçus HTTP vérifiés, 18 scripts, 25 références statiques sans appel et sept
ressources non HTML en HTTP 200 contre deux initialement. Trois candidats JS
renvoient le shell générique et restent non confirmés. Gobuster reste partiel
sur le wildcard ; ffuf termine. Limites d’analyse/provenance atteintes ; les
quatre endpoints précédemment guidés par wordlist ne sont pas retrouvés en
HTTP. Aucun exploit ni accès hors origine ; laboratoire arrêté et mandats
révoqués. Les archives privées précédentes restent inchangées.

Validation M2.1 : suite régulière complète, **1 045 réussis, 0 échec et 94
ignorés sous chacun de Python 3.12 et 3.14**. Les 94 cas hôte ne sont pas tous
qualifiés par cette suite ; séparément, `ARGOS_TEST_NETWORK=1` avec les chemins
slirp ci-dessus et `pytest -q tests/test_recon_network.py` donne **8 réussis,
0 échec, 0 ignoré sous chaque version**, dont HTML → modules JS → route publique,
budgets, périmètre, redirection, timeout et annulation. Ruff, formatage et
Pyright passent. Aucune modification du frontend ou dépendance ajoutée.

## M2.1.1 — Registre administrateur et diagnostic

Le registre TOML version 1 est optionnel, chargé exclusivement depuis
`ARGOS_TOOL_REGISTRY` (ou `doctor --registry`). Aucun chargement depuis une
mission, une cible, le modèle ou un `.env` automatique. Sans configuration,
les adaptateurs utilisent les installations `/usr/bin`, indépendamment du PATH.
Avec un registre explicite, un outil absent/modifié ne choisit aucun repli.
Les anciens reçus et la baseline Juice Shop restent inchangés.

```toml
schema_version = 1
[tools.gobuster]
path = "gobuster/gobuster" # relatif au registre, ou chemin absolu administrateur
version = "3.8.2"
source = "https://github.com/OJ/gobuster"
binary_sha256 = "REMPLACER_PAR_64_CHIFFRES_HEXADECIMAUX"
data_directory = "gobuster"
```

Les métadonnées supplémentaires du registre d'installation sont conservables.
Seuls les cinq identifiants connus sont admis. Le fichier doit être régulier,
appartenir à l'administrateur courant/root et ne pas être remplaçable par un
autre compte via ses permissions ou celles de ses parents. Les chemins relatifs
et `~` sont supportés ; aucun chemin personnel n'est intégré au moteur.

Nmap, Gobuster et ffuf sont les seuls outils opérationnels. Hashcat/John sont
inventoriés avec leur empreinte, sans adaptateur d'attaque. Pour Nmap,
`data_directory` désigne le répertoire de données de son installation : bases
services/probes, moteur NSE, scripts de catégorie **version** nécessaires au
`-sV` existant et bibliothèques Lua/données. Cela n'ajoute ni `-sC`, ni arguments
libres. Le registre épingle les données à son chargement, les profils/preuves
conservent les empreintes avant lancement ; chaque ressource est revérifiée
lors de la création des instantanés scellés montés en lecture seule.
Voir la [décision de montage](../architecture/adr/0003-recon-tool-relay.md).

```bash
export ARGOS_TOOL_REGISTRY=/chemin/admin/tools/registry.toml
export ARGOS_WORDLIST_HOME=/chemin/admin/wordlists
python -m argos doctor
# Les options --slirp et --slirp-library réutilisent les dépendances réseau
# configurables du CLI recon, si elles ne sont pas aux emplacements système.
```

`doctor` produit du JSON lisible et ne lance ni outil recensé, ni scan, ni
requête réseau. Versions déclarées par le registre (ou métadonnées du paquet
système), SHA-256, données, dépendances ELF directes et prérequis sont affichés.
`readelf`/`ldconfig` inspectent les dépendances sans exécuter le binaire examiné.
Une compatibilité d'adaptateur n'est pas une qualification de tous les backends,
des dépendances transitives, du GPU ou des namespaces. Les bibliothèques hors
`/usr` ne sont pas ajoutées aux montages des trois adaptateurs opérationnels.
`ARGOS_WORDLIST_HOME` indique seulement la présence du corpus ; la sélection
reste explicite via les deux options wordlist existantes et leurs bornes.

Les paquets système restent installés. Avant suppression : qualifier les trois
adaptateurs, `-sV`, leurs données, arrêt/révocation, budgets et confinement avec
les installations choisies ; vérifier les autres consommateurs du poste et la
stratégie de déploiement. Les nouvelles versions des outils doivent être
séparées de tout effet du moteur dans une future comparaison de couverture.

Validation M2.1.1 (24 novembre 2026) : **1 097 réussis, 0 échec, 98 ignorés**
pour la suite régulière sous chacun de Python 3.12/3.14 ; les cas hôte optionnels
ne sont pas tous activés par cette suite. Séparément, **86 réussis, 0 échec,
0 ignoré par version** sur `test_tool_registry.py`, `test_recon_network.py`,
`test_network_worker.py` et `test_isolated_worker.py`, avec
`ARGOS_TEST_ISOLATION=1 ARGOS_TEST_NETWORK=1 ARGOS_TEST_TOOL_REGISTRY=<registre>`
et les deux chemins slirp configurés. Les quatre variantes pipeline utilisent
les binaires système/manuels et avec/sans `-sV`, sur une fixture locale signée.
Les assertions hôte contrôlent aussi FSIZE/NOFILE effectifs après préparation,
les montages scellés et l'absence d'accès aux fichiers privés.

Installations manuelles exercées : Nmap 7.992 (NPSL 0.95, fichier LICENSE de
l'archive officielle), Gobuster 3.8.2 (Apache-2.0) et ffuf 2.3.0 (MIT) ; leurs
sources, versions et empreintes sont dans le registre administrateur, non dans
une mission. Hashcat 8.0.0 et John Jumbo figé sont seulement vérifiés par
inventaire. Ruff, formatage et Pyright passent. Les 73 fichiers du manifeste
M2.0.1 sont identiques ; aucun nouveau scan Juice Shop, test externe ou gain de
couverture attribué au moteur. Aucun paquet système désinstallé.
