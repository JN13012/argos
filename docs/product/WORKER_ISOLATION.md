# P1.4 — Isolation des workers

État du 16 novembre 2026 : **P1.4.1 livré localement ; P1.4 reste ouverte**.
Le worker sans réseau est qualifié. L'accès réseau limité aux cibles autorisées
et son intégration au moteur Nmap restent à construire.

## Livrable P1.4.1

`argos.backend.core.isolated_worker.OfflineWorker` est une primitive Linux
séparée du moteur ATTACK. Elle exécute un programme système avec des arguments
sans shell ; elle n'est ni un outil exposé à l'agent, ni une autorisation de
mission, ni un adaptateur de scan actif.

Le lancement crée une unité utilisateur systemd temporaire et un gardien
de confiance. Avant d'exécuter l'outil, ce gardien contrôle les valeurs
effectives des cgroups v2 et limites de processus. Il refuse l'exécution si
un contrôle requis manque ou diffère du profil. Bubblewrap crée ensuite des
namespaces privés : réseau, PID, utilisateur, IPC, UTS, cgroup et montages.
Les mécanismes d'isolation ne sont jamais remplacés par une exécution directe.

| Contrôle | Profil par défaut et comportement |
| --- | --- |
| Mémoire | 256 Mio pour l'unité et ses descendants ; swap désactivé |
| CPU | 50 % d'un CPU, vérifié dans `cpu.max` |
| Processus et threads | 16 tâches au total dans le cgroup |
| Temps | 10 secondes côté runtime ; limite systemd de secours de 12 secondes |
| Espace temporaire | Deux tmpfs privés, `/tmp` et `/work`, 8 Mio chacun ; consommation également soumise au quota mémoire |
| Sorties et fichiers | Limite noyau de 1 Mio par fichier, y compris les sorties héritées ; lecture de chaque sortie limitée à 1 Mio ; budget de sortie entièrement rempli classé en échec par prudence |
| Descripteurs et core dumps | 64 descripteurs maximum ; core dumps désactivés |
| Fichiers de l'hôte | `/usr`, `/lib`, `/lib64` et `/bin` montés en lecture seule lorsqu'ils existent ; home, dépôt, bases et bus utilisateur absents |
| Privilèges | `NoNewPrivileges`, capabilities supprimées, création de nouveaux user namespaces désactivée |
| Réseau | Namespace privé sans liaison avec celui de l'hôte ; aucun accès aux cibles de mission |

La racine, `/proc` et `/dev` sont remontés en lecture seule. L'environnement
de l'outil est reconstruit avec seulement `PATH`, `LANG` et `HOME`. Les
programmes doivent provenir d'un chemin absolu résolu sous `/usr`. Cela décrit
un montage logiciel de confiance, pas un catalogue de capacités autorisées :
ce catalogue et sa politique restent des responsabilités du runtime métier.

## Arrêt et descendants

Le runtime conserve seul l'extrémité écriture d'un pipe de vie. L'outil reçoit
`/dev/null` comme entrée, pas ce pipe. À la fermeture du pipe, y compris lors
d'une mort brutale du runtime, le gardien arrête le processus bubblewrap qu'il
vient de créer. La fermeture du namespace PID et `KillMode=control-group`
complètent le nettoyage, même pour un descendant qui a créé une autre session.
Le délai systemd borne aussi la durée de vie si le gardien reste bloqué.

L'annulation et le timeout ferment le pipe ; la fin du client systemd est
attendue. Un dépassement du délai de nettoyage déclenche un arrêt de l'unité
nommée par un UUID et une erreur explicite. Aucun PID provenant d'une ancienne
base n'est réutilisé. Les sorties renvoient un état et un code ; un échec de
configuration reste un échec, jamais une preuve que l'outil a fonctionné.

## Qualification exécutée

Linux/WSL, noyau `6.18.58.1-microsoft-standard-WSL2`, systemd 259.5,
bubblewrap 0.11.1,
interpréteur système Python 3.14.4 pour le gardien. Le client Argos est testé
avec Python 3.12.15 et 3.14.6. Aucun paquet n'a été installé et aucune
configuration permanente de systemd ou du réseau n'a été modifiée.

```sh
# Qualification complète sur l'hôte, avec bus systemd utilisateur accessible.
ARGOS_TEST_ISOLATION=1 .venv/bin/python -m pytest -q -o faulthandler_timeout=10

# Qualification du composant seul.
ARGOS_TEST_ISOLATION=1 .venv/bin/python -m pytest -q tests/test_isolated_worker.py
```

Résultats : **272 tests passent sous Python 3.12 et 272 sous Python 3.14**,
dont 24 tests du nouveau composant. Dix de ces tests exigent l'hôte réel et
sont explicitement ignorés sans `ARGOS_TEST_ISOLATION=1` : la suite par défaut
donne **262 réussites et 10 ignorés**. Ruff, formatage global et Pyright passent.
Les essais sont locaux, sans Nmap ni scan réel. Aucune unité temporaire de
qualification ne reste active après les essais. La CI distante n'a pas été
exécutée et sa configuration actuelle n'active pas ces dix essais hôte.

Les essais vérifient les fichiers et secrets absents, la racine non modifiable,
le refus d'une connexion vers un serveur TCP de boucle locale de l'hôte,
la saturation d'un tmpfs par plusieurs fichiers, le refus de création de
processus, une allocation supérieure au quota mémoire, le temps CPU consommé,
la limite de sortie même si l'outil ignore une écriture partielle et retourne
zéro, l'annulation, le timeout et la disparition d'un descendant
détaché après la mort du runtime. Un test rejette un profil dont les contrôles
n'ont pas été appliqués avant tout lancement de l'outil.

## Pourquoi le réseau actif reste ouvert

Le test d'environnement a utilisé deux sockets TCP contrôlées, sur
`127.0.0.1` et `127.0.0.2`, avec une unité utilisateur demandant
`IPAddressDeny=any` et `IPAddressAllow=127.0.0.1/32`. **Les deux connexions
ont réussi.** Ce réglage ne constitue donc pas une barrière de sécurité sur
cet hôte. La [documentation systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#IPAddressAllow=)
précise que des réglages IP peuvent être sans effet selon les fonctionnalités
du système. Le worker livré utilise un namespace sans réseau plutôt que ces
options. Docker n'est pas disponible localement ; aucun démon n'a été démarré.

## P1.4.2 — Réseau de mission et intégration ATTACK

Le livrable suivant doit être un adaptateur de réseau restreint, puis son
branchement dans `ExecutionManager`. Le moteur actif existant n'utilise pas
encore `OfflineWorker` : ses limites historiques sur les processus et les
sorties restent celles documentées dans le [durcissement](PENTEST_P135_HARDENING.md).

Le contrat à implémenter doit porter : identifiant du job et de mission,
cible IP littérale, ports et protocole, limites, échéance et version du profil.
Le réseau est configuré avant le lancement de l'outil, avec refus par défaut.
Le composant privilégié éventuel ne reçoit ni shell, ni propriétés systemd
arbitraires, ni chemins de montage fournis par le modèle. Deux options restent
à qualifier : réseau rootless avec interface dédiée et pare-feu dans son
namespace, ou service système restreint avec filtrage noyau vérifié.

Critères de sortie :

1. La cible et les ports autorisés sont joignables ; des témoins hors périmètre
   sont bloqués, en IPv4 et IPv6, y compris loopback, DNS et sorties indirectes.
2. L'absence ou l'échec de la barrière réseau empêche le lancement ; aucun
   mode réseau hôte ni repli silencieux n'est permis.
3. Le mandat est revérifié par le moteur avant lancement ; annulation,
   révocation et expiration arrêtent le worker et ses descendants.
4. L'identité et la version du profil d'isolation sont liées à la demande
   persistée et aux preuves ; les erreurs ne produisent pas de faux succès.
5. La qualification couvre saturation, dépassements et crash après lancement
   du véritable adaptateur. P1.5 conserve la qualification Nmap en labo autorisé.

## Limites de ce lot

Ce worker partage le noyau et les logiciels système de l'hôte. Il ne constitue
pas une VM ni une preuve de résistance à toute vulnérabilité du noyau. Il ne
lit aucun fichier de mission et ne persiste pas lui-même les résultats dans
`JobStore`. Les dépendances système et le gardien doivent être présents et
de confiance ; une machine ou un compte administrateur compromis restent
hors de ses garanties. L'isolation des scans actifs n'est pas annoncée livrée.

Les primitives sont décrites dans le
[manuel bubblewrap](https://github.com/containers/bubblewrap/blob/main/bwrap.xml),
la [documentation cgroups v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
et les [règles d'arrêt systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html).
