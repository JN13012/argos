# M2.3 — Network Recon Engine

Validé sur fixtures et laboratoires locaux le 24 novembre 2026 ; branche dédiée
non fusionnée et non publiée.

## Audit initial (24 novembre 2026)

- `ScanPlanner` : 22 ports TCP communs puis identification facultative des ports
  ouverts communs ; pas de profil réseau ni orchestration multi-hôtes.
- `AuthorizedNmapRunner.prepare` : signature, scope IP et action contrôlés et
  audités avant admission/lancement ; 32 ports maximum, pas de shell libre.
- `ExecutionManager`, `JobStore`, `EvidenceStore` : état durable, preuve XML,
  profil d'isolation lié au reçu, arrêt/révocation, reprise explicite sans replay.
- `NetworkWorker` : une IP et 32 ports TCP par namespace, refus hors destination,
  unprivileged `-sT -Pn -n -T2`, max-retries 1, host-timeout 60 s, worker 75 s.
- Le parseur conserve seulement port/état/service/version ; il ignore les états
  agrégés `extraports`, l'état hôte et la provenance de l'identification.
- Le pipeline web n'expose qu'une IP et une tranche de ports ; il conserve déjà
  les UUID de jobs. Le CLI historique et ses autorisations restent compatibles.
- Aucun composant produit nommé State séparé n'existe : l'état opérationnel est
  `JobStore` et les bilans `ReconStore`. Ceux-ci restent les points de stockage.

## Contrat

Extension du planner et du chemin Nmap existants, avec commandes réseau seules
sous `recon`. Aucun second worker, transport ou magasin d'observations.
Les profils sont des plafonds opératoires locaux, pas des autorisations ; les
signatures continuent de porter scope/actions/expiration. Les profils ne sont
pas encore un contrat de budgets réseau signé. Chaque job et chaque lancement
revalident le grant. Aucune expansion de CIDR ni suivi d'adresse découverte.
Les cibles IP sont fournies explicitement, bornées, et toutes validées avant
le premier lancement. Les exclusions du mandat restent prioritaires.

| Profil | Hôtes maximum | Ports TCP par hôte maximum | Jobs maximum | Fenêtre d’exécution |
| --- | --- | --- | --- | --- |
| Quick | 1 | 32 | 1 | 75 s |
| Standard | 4 | 128 | 16 | 300 s |
| Deep | 8 | 256 | 64 | 900 s |

Ports explicites obligatoires, découpés en tranches de 32 au plus. Concurrence 1,
75 s maximum par worker, 60 s par hôte Nmap, une relance Nmap maximum par sonde.
Le budget de durée commence après la prévalidation sans trafic et commande
l'annulation ; le nettoyage peut dépasser cette échéance. Le plafond de jobs
est déduit du nombre hôtes × tranches. Le profil ne prétend
pas couvrir tous les ports ; Deep désigne une enveloppe plus large. `-sV` reste
une option explicite soumise à `service_identification`, sans nouvelle logique
de fingerprinting M2.4, NSE, UDP, raw socket, OS detection ou exploitation.

Le bilan distingue couples hôte/port demandés, admis en job, observés, non
résolus et non soumis. Les ports fermés agrégés ne sont développés que si une seule classe
agrégée rend l'affectation exacte. Aucune absence n'est interprétée comme fermé.
Les observations ne sont remises qu'après vérification du reçu et de sa liaison
au job/mission/cible/phase. L'identification déclarée par Nmap reste une
observation (méthode/confiance), jamais une vulnérabilité ou un fingerprint validé.

## Limites

TCP connect seulement, liste IP explicite, pas de découverte de sous-réseau,
pas de DNS ni d'UDP, pas de qualification externe/production. Les compteurs
portent sur les couples demandés et admis, pas sur la preuve du lancement de
chaque sonde ni sur le nombre de paquets émis. Les
budgets ne sont pas globaux entre bases ou exécutions successives. Une erreur,
un arrêt, un crash ou un XML incomplet ne prouve pas une absence de service.
Le bilan est une projection des jobs/preuves, pas une base d'actifs concurrente.

## CLI

`network-init` prépare le scope numérique à faire signer par l'autorité hors
ligne ; il n'émet aucun grant. L'activation utilise `web activate` comme le
pipeline existant. Les ports du run sont obligatoirement explicites. Un mandat
IP existant peut être réutilisé si toutes les cibles et actions sont permises.

```bash
python -m argos recon network-init --target-ip 127.0.0.1 \
  --additional-target-ip ::1 --reference laboratoire-local
# Revue/signature hors ligne, puis activation du mandat existant.
python -m argos recon network-plan --mission-id UUID_IP \
  --targets 127.0.0.1,::1 --ports 22,80,443 --network-profile standard
python -m argos recon network-run --mission-id UUID_IP \
  --targets 127.0.0.1,::1 --ports 22,80,443 --network-profile standard \
  --public-key /chemin/prive/reviewer.pub.pem
python -m argos recon network-report --run-id UUID_RECON
```

`--db`, `--slirp` et `--slirp-library` réutilisent la configuration existante.
`--identify-versions` est facultatif. Quick ne lance pas automatiquement une
seconde phase d'identification ; tous les profils utilisent les ports fournis.
Le plan reste hors réseau et indique `grant_verified=false` ; seul le runtime
vérifie la signature. Code 0 : tous les couples explicitement demandés ont un
état reconnu ; 3 : résultat partiel ; 130 : signal ; erreurs d'entrée/autorisation
et de stockage suivent le CLI existant. Aucun replay ni poursuite automatique
après crash. `network-report` relit les jobs et vérifie leurs reçus, la liaison
mission/cible/ports et l'égalité des observations ; une projection modifiée,
même réhachée, ne suffit pas à remplacer les preuves. Cette vérification n'est
pas une signature d'authenticité contre un administrateur de la base.

Les champs `host_state/host_reason` conservent la déclaration Nmap : avec `-Pn`,
`up/user-set` ne prouve pas une réponse de l'hôte. Les champs service, version,
product, extra_info, tunnel, service_method et service_confidence sont les
observations de Nmap, liées au reçu source ; `table` n'est pas `probed` et la
confiance 0–10 n'est pas une probabilité de vulnérabilité. Ils préparent un
contrat d'entrée pour M2.4, sans implémenter son moteur. Les reçus historiques
restent lisibles sans réécriture, avec valeurs absentes laissées inconnues.

Le bilan compte `requested_pairs`, `admitted_pairs` (un UUID de job a été
attribué), `observed_pairs`, `unresolved_pairs` et `unsubmitted_pairs`. Une
admission n'atteste pas qu'une sonde a atteint la cible. Les classes d'état,
services identifiés par sonde, jobs en erreur et motifs d'arrêt complètent la
couverture. Une observation `unknown` ne compte pas comme état établi. Une
exécution bornée complète ne couvre ni les ports non demandés ni les autres
protocoles. Les métadonnées et XML restent dans la base privée existante.

## Qualification

Fixtures sans correction fournie à l'agent : deux serveurs locaux connus,
HTTP et bannière SSH simulée, sur loopback IPv4/IPv6 ; sockets liées mais non à
l'écoute pour les ports fermés. L'oracle de test connaît les ports ouverts ;
le moteur reçoit seulement les IP et la liste de ports autorisés. Aucun accès
aux solutions, flags ou scoreboard, aucun Juice Shop, aucune exploitation.
Les services et threads sont arrêtés ; les grants éphémères sont révoqués dans
les finalizers, y compris en cas d'échec.

Les essais initiaux Standard/Deep ont révélé le défaut d'assemblage d'un worker
sans limites explicites (10 s par défaut). Le run utilise désormais explicitement
75 s et 2 000 000 octets, conformément aux plafonds existants. Ces pilotes en
échec ne sont pas présentés comme qualification. Les essais finaux sont décrits
ci-dessous ; les durées ne sont pas des comparaisons de vitesse.


Résultats mesurés sur la liste demandée (aucun état manquant) :

| Profil | Hôtes × ports | Jobs | Ouverts / fermés | Identifications sondées | Temps 3.14 / 3.12 |
| --- | --- | --- | --- | --- | --- |
| Quick, CLI réel | 1 × 3 | 1 | 2 / 1 | HTTP et SSH simulé | 9,75 / 9,51 s |
| Standard | 2 × 33 | 4 | 4 / 62 | Non demandées | 33,70 / 33,18 s |
| Deep | 2 × 65 | 6 | 4 / 126 | Non demandées | 62,70 / 62,28 s |

Ces essais ne saturent pas les maxima de 4/8 hôtes ou 128/256 ports par hôte.
Les maxima et rejets sont vérifiés par fixtures de planner hors réseau, pas
qualifiés à charge maximale sur cet hôte. Les ports `filtered` et les agrégats
ambigus sont des fixtures XML, sans qualification physique de pare-feu distant.
Aucun taux de détection de vulnérabilités ni gain de vitesse n'en est déduit.

Commandes de validation (configuration administrateur permanente chargée avec
`ARGOS_PROJECT_HOME=$PWD`, puis `source ~/.config/argos/environment.sh`) :

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
.venv/bin/python -m pytest -q -o faulthandler_timeout=30
/tmp/argos-stabilization-py312/bin/python -m pytest -q -o faulthandler_timeout=30
ARGOS_TEST_NETWORK=1 .venv/bin/python -m pytest -q -s \
  tests/test_network_recon_host.py tests/test_network_worker.py \
  -o faulthandler_timeout=30
ARGOS_TEST_NETWORK=1 /tmp/argos-stabilization-py312/bin/python -m pytest -q -s \
  tests/test_network_recon_host.py tests/test_network_worker.py \
  -o faulthandler_timeout=30
git diff --check
```

Suite régulière finale : **1 131 réussis, zéro échec, 109 ignorés** par version
(95,94 s sous 3.14 ; 96,98 s sous 3.12). Ces ignorés ne sont pas une qualification
hôte. Ruff, formatage, Pyright (zéro erreur) et liens locaux passent.
Le test de lecture d'un reçu au format précédent conserve son empreinte ;
la fixture d'altération de projection réhachée est refusée par les preuves.

Qualification hôte 3.14 : l'invocation combinée a donné **36 réussis et un
échec de fixture Quick** (base créée en 0644). Le CLI a correctement refusé
cette base ; le finalizer a révoqué le grant. Après correction de la fixture en
0600, Quick/CLI et altération de projection donnent **un réussi, zéro échec**
par version (11,76 / 11,26 s). Les autres 36 cas 3.14 comprennent profils,
arrêt/révocation/durée, interdictions d'autres destinations, FS privé, erreurs
setup, reprise sans repli et mort du parent. Aucun cas hôte ignoré dans cette
invocation ; le résultat est décrit par invocation, sans masquer son échec.

La première invocation combinée 3.12 a subi un crash natif de l'interpréteur
(code 139 pendant Deep), sans cause établie. Le grant de cet essai a été révoqué
explicitement ; jobs et bilan ont été réconciliés en interrompus, sans replay.
La reprise séquentielle donne **37 réussis, zéro échec, zéro ignoré**, 129,73 s.
Tous les cas de cette sélection sont ainsi qualifiés sous 3.12 ; sous 3.14,
les 36 cas réussis et le Quick corrigé couvrent les mêmes 37 cas, en deux
invocations. Le crash natif n'est pas attribué au produit sans preuve de cause.

Les journaux, les manifestes et copies des bases de fixtures sont conservés
hors Git dans `.argos/qualifications/m23/`. Les essais contrôlent HTTP/SSH simulé,
les ports fermés, les reçus et le confinement ; ils ne qualifient pas l'isolation
globale d'un futur agent LLM ou tous les scénarios du système.

La version et les licences des outils restent celles du [lot recon existant](WEB_RECON.md#m211--registre-administrateur-et-diagnostic).
Aucune nouvelle dépendance ou installation. CI distante M2.3 non exécutée,
branche non publiée ; les suites navigateur/isolation complètes optionnelles
n'ont pas été relancées pour cette tranche sans changement de leur code.
Aucun changement frontend, scan externe ou exploitation. M2.4 non commencé.

## Consolidation M2.3 — investigation du crash 3.12

Base : `056a6ae`, arbre propre. L'archive du processus arrêté au code 139 se
termine au milieu du second dump différé `faulthandler`, dans `tomllib`, sans
message Python fatal complet, pile C ou core exploitable (`ulimit -c` vaut 0).
Cela situe l'arrêt pendant le diagnostic ; cela ne prouve ni un défaut de
`tomllib`, ni la cause racine. Les courses connues du watchdog CPython, par
exemple [gh-140815](https://github.com/python/cpython/issues/140815), constituent
une piste seulement : son scénario de finalisation n'est pas celui démontré
ici. Aucun changement arbitraire de version ou retrait de `faulthandler`.

L'archive exacte de Deep contient deux jobs `completed`, reçus et profils
vérifiés, puis une étape sans UUID de job, réconciliée `interrupted/runtime_lost`.
Aucun job en cours ni observation fabriquée à cet endroit. Les huit bases
archivées contiennent 19 jobs terminés ; leurs reçus et liaisons aux profils
passent tous la relecture `JobStore.get`. Une base Quick refusée en amont ne
contient aucun job. Le grant de l'essai interrompu reste révoqué.

Reproduction ciblée : Deep sous Python 3.12.15 avec `PYTHONMALLOC=debug`,
`-X dev` et `faulthandler_timeout=30` : **un réussi**, 65,41 s ; crash non
reproduit. La qualification réseau 3.12 renouvelée donne **32 réussis, zéro
ignoré**, 12,59 s. Le test de mort du parent couvre maintenant `SIGKILL` et
`SIGSEGV` : le processus s'arrête au signal attendu, le cgroup devient vide,
helpers et descendant détaché disparaissent, sans attendre la limite worker.
Il simule les conséquences d'un crash, sans prétendre en reproduire la cause.
Les refus d'autres IP/ports/protocoles, les échecs setup, arrêt/révocation et
absence de repli sont exercés par la même sélection.

Commandes : configuration administrateur permanente, `ARGOS_TEST_NETWORK=1`,
puis Python 3.12 `pytest -q tests/test_network_worker.py`, et
`PYTHONMALLOC=debug python -X dev -m pytest -q tests/test_network_recon_host.py
-k deep -o faulthandler_timeout=30`. Les suites régulières 3.12/3.14, lint,
formatage et typage sont renouvelés avant intégration. Les journaux restent
privés dans `.argos/qualifications/m23-consolidation/`.

Conclusion bornée : aucune atteinte à l'isolation, aux preuves ou au nettoyage
n'est démontrée ; les conséquences testées du crash sont prises en charge.
La cause native reste non établie faute de core/reproduction. Elle reste une
limite documentée, pas une qualification universelle de l'interpréteur.
Les limites réseau du contrat restent inchangées : TCP/IP explicites, plafonds
par exécution non signés, absence d'UDP/DNS/sweep, maxima non qualifiés en charge
et aucune qualification externe. Aucun blocage produit identifié dans ce lot.

Validation de consolidation : **1 131 réussis, zéro échec, 110 ignorés** pour
la suite régulière sous 3.12 (90,13 s) et 3.14 (89,76 s) ; le cas supplémentaire
ignoré est le nouveau SIGSEGV hôte, qualifié séparément. Ruff, formatage,
Pyright et `git diff --check` passent. Intégration M2.3 autorisée par cette
consolidation ; la qualification reste locale et limitée aux scénarios décrits.
