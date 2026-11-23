# Reconnaissance Nmap → Gobuster → ffuf

Lot validé localement le 23 novembre 2026. Le pipeline CLI enchaîne Nmap,
découverte HTML, Gobuster `dir`, ffuf sur chemins de fichiers, puis exploration
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
