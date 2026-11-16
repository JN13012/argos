# P1 — Exécution durable et isolée

Suivi du 16 novembre 2026. Ce lot prépare le runtime des missions autonomes.
Il ne connecte aucun agent et n'ajoute aucun outil offensif.

## P1.1 — Capacité et cache terminal

Implémenté et validé localement dans le commit `571aa39` :

- `max_jobs` limite uniquement les jobs `pending` et `running`, sous le même
  verrou que l'admission. Sa valeur par défaut reste 32.
- `concurrency` limite les workers ; sa valeur par défaut reste 2.
- `max_completed_jobs` limite séparément le nombre de jobs terminaux en mémoire
  (succès, échec, annulation ou timeout). Valeur par défaut : 32 ; plage : 1–256.
  Les plus anciens par ordre de finalisation sortent du cache en premier.
- L'audit des transitions est désormais enregistré par défaut dans la base de
  mission. Un chemin d'audit explicite reste possible. Les preuves ne sont pas
  supprimées quand un job sort du cache.

Avec les valeurs par défaut, le gestionnaire conserve au maximum 32 jobs actifs
et 32 jobs terminaux dans son registre. Il s'agit d'une limite en nombre de
jobs, pas d'un quota mémoire imposé par le système.

À la livraison de P1.1, `get()` et `result()` retournaient `None` après éviction.
P1.2 ajoute les lectures sur disque décrites ci-dessous. Le cache reste borné et
aucune suppression des preuves ou de l'audit sur disque n'est introduite.

Les tests vérifient :

- 12 soumissions concurrentes pour une capacité de 3 : exactement 3 admises ;
- réutilisation de la capacité après succès, échec, annulation et timeout ;
- 40 jobs successifs avec une capacité active de 1 et un cache terminal de 2 ;
- éviction des anciens résultats, conservation des jobs récents, de chaque
  preuve et des transitions sur disque ;
- rejet des bornes de cache invalides et maintien des tests de révocation.

Les sous-processus de test sont simulés ou synthétiques ; aucun scan réel.

Vérification locale : 193 tests Python passent sous Python 3.14 ; les 25 tests
ciblés d'exécution, de processus, d'autorisation et d'orchestration passent
également sous Python 3.12. Ruff, son contrôle de formatage et Pyright passent
sur l'ensemble du Python. Ces nombres décrivent la clôture de P1.1.

## P1.2 — Demandes et résultats persistants

Implémenté et validé localement dans le commit `ecaf368` :

- `JobStore` ajoute la table `pentest_jobs` et un index par mission, sans
  supprimer les tables existantes. La demande contient les identifiants,
  la cible, les dates, l'état, l'erreur et le plan JSON versionné (phase,
  ports, identification de versions et justification).
- La demande `pending` et son événement d'audit sont validés ensemble avant
  admission dans le pool. La transition `running` est persistée avant lancement.
- Une transition terminale valide l'état, les preuves, leur reçu et l'audit
  dans une seule transaction SQLite. Un échec annule l'ensemble de cette
  transaction. Les identités de demande et les transitions sont contrôlées.
- `ExecutionManager.get()` et `result()` utilisent le stockage après éviction
  ou redémarrage ; les lectures terminales vérifient les preuves et leur
  correspondance avec le job. `request()` donne aussi le plan.
  `JobStore.list_for_mission()` liste les identifiants avec pagination bornée.
- Une erreur d'écriture bloque les nouvelles admissions dans ce gestionnaire.
  Le job concerné expose `JobPersistenceError`, sans présenter de faux succès ;
  les autres workers vérifient ce blocage avant lancement et durant leur boucle
  de surveillance. L'orchestrateur s'arrête sur erreur de lecture ou d'écriture.
- Un échec de soumission au pool laisse un échec terminal enregistré, si le
  stockage reste disponible.

La base canonique est `evidence_path`, ou la base de mission par défaut. Elle
contient demandes, audit canonique et preuves. Un `audit_path` différent reste
supporté comme miroir supplémentaire : ce miroir n'est pas atomique avec la
base canonique. Son échec bloque aussi le gestionnaire ; une demande ou un
résultat déjà validé dans la base canonique peut alors y subsister. Le mode
`:memory:` est refusé pour le gestionnaire d'exécution.

P1.2 ne fournissait ni réconciliation ni exclusion entre gestionnaires : les
états non terminaux restaient ceux de la dernière écriture, même après une
panne. P1.3 ci-dessous décrit la propriété et la réconciliation actuelles.

Les anciens événements et preuves restent lisibles par leurs magasins
historiques. Aucun plan manquant n'est inventé pour créer une demande ancienne.
Les reçus détectent des incohérences ; ils ne protègent pas contre un acteur
capable de réécrire toute la base. Les droits de mission et les quotas système
restent des contrôles distincts.

Validation : **227 tests passent sous Python 3.12 et 227 sous Python 3.14**.
Ruff, formatage global et Pyright passent. Les tests couvrent la réouverture,
les quatre états terminaux, l'éviction, les transitions refusées, les preuves
manquantes ou incohérentes, les erreurs SQLite à l'admission, au démarrage et
à la finalisation, le rollback des preuves et de l'audit, l'échec du pool et
les chemins de stockage séparés. Aucun scan réseau réel ; frontend inchangé
et CI distante non exécutée pour ce lot. Ces résultats décrivent P1.2.

## P1.3 — Propriété, réconciliation et reprise explicite

Implémenté et validé localement. Le runtime prend un verrou POSIX `flock`
exclusif et non bloquant sur le fichier SQLite canonique, avant toute
réconciliation ou création de workers. Un second gestionnaire d'exécution
sur la même base est refusé ; les lectures directes par `JobStore` restent
possibles. Le verrou porte sur l'inode : un alias par lien dur ne permet pas
de contourner l'exclusion. Il est libéré après l'arrêt des workers, à la mort
du processus ou si l'initialisation échoue.

Chaque runtime possède un UUID. Les nouvelles demandes portent cet identifiant
dans `pentest_job_owners` ; les transitions vérifient le propriétaire attendu.
Un transfert de propriété d'un job en attente vérifie son ancien propriétaire
dans une transaction SQLite. Les tables existantes sont conservées ; une
ancienne demande sans propriétaire peut être reprise après contrôle du mandat.

Au démarrage, sous le verrou exclusif :

| Dernier état | Traitement |
| --- | --- |
| `pending` | Conservé en attente, aucun lancement automatique |
| `running` | Passage atomique à `interrupted`, avec audit, reçu de réconciliation et motif « résultat du processus inconnu » |
| État terminal | Conservé, aucune réexécution |

Le reçu `interrupted` ne prétend pas décrire une sortie d'outil : code de
sortie, XML et observations sont absents, les arguments inconnus sont vides.
Sa date de fin est celle de la réconciliation, pas une preuve de l'heure
d'arrêt du processus. La réconciliation est idempotente et chaque transition
est atomique avec les preuves, l'audit et le journal de récupération.

`ExecutionManager.resume(job_id, reason=...)` peut reprendre uniquement une
demande `pending`. L'appel conserve son identifiant et son plan, vérifie la
capacité, exige un motif de 1–1000 caractères et revérifie le mandat complet
(signature, validité, cible et action). Le worker revérifie encore le mandat
avant lancement. Une reprise refusée pour révocation, expiration ou cible hors
périmètre ne transfère pas la propriété. Des appels concurrents ne peuvent
programmer qu'une seule fois le même job. Un job `interrupted` ne peut pas être
rejoué par cette API.

« Explicite » désigne un appel du moteur de mission avec un motif enregistré ;
cela n'impose pas une nouvelle validation humaine pour chaque étape déjà
autorisée. `pentest_job_recovery` et `JobStore.recovery_events()` conservent la
décision, le motif, la date et les identifiants des anciens et nouveaux
propriétaires. Un `audit_path` séparé reste un miroir non atomique ; son échec
ne supprime pas la décision déjà validée dans la base canonique.

Limites :

- La qualification porte sur Linux/WSL et une base locale. Le gestionnaire
  refuse une plateforme sans POSIX `flock`. Windows natif, systèmes de fichiers
  réseau et déploiements multi-hôtes ne sont pas qualifiés.
- L'exclusion vaut pour les runtimes coopérants utilisant le même fichier de
  base. Des bases distinctes ou les runners synchrones historiques ne partagent
  pas cette limite. Aucun accès direct en écriture à la base ne doit être
  exposé à l'agent.
- Un sous-processus peut survivre à la mort du superviseur. La réconciliation
  ne déduit pas sa mort d'un PID et ne lui envoie aucun signal. P1.4 doit ajouter
  l'isolation et le nettoyage du groupe de processus par le système.
- Les jobs historiques `pending` restent non programmés jusqu'à `resume()` ;
  ils n'occupent pas la file active en mémoire. Les quotas système et la
  rétention sur disque ne sont pas fournis par ce verrou.
- L'orchestrateur de mission n'est pas lui-même repris automatiquement : P1.3
  fournit la reprise de demandes non démarrées et la classification prudente
  des exécutions incertaines, sans garantir l'exécution exactement une fois
  de tous les effets externes d'une mission.

Validation : **248 tests passent sous Python 3.12 et Python 3.14**, Ruff,
formatage global et Pyright propres. Les tests incluent les sorties brutales
d'un runtime avant mise en exécution, juste avant lancement et après lancement
d'un outil synthétique ; l'exclusion entre processus et après lien dur ; la
libération du verrou à la mort de son propriétaire ; les courses de reprise et
de transfert de propriété ; les refus de mandat et de transitions ; le rollback
du journal de réconciliation. Aucun scan réseau réel. CI distante non exécutée.

## Livraisons suivantes

| Lot | Travail | Critères de sortie |
| --- | --- | --- |
| P1.4 — Isolation | Exécuter dans un worker séparé ; appliquer les quotas CPU, mémoire, processus et disque et les restrictions réseau | Dépassements arrêtés par le système ; sorties hors périmètre bloquées ; nettoyage des descendants vérifié |
| P1.5 — Qualification | Scénarios de saturation, crash, reprise, révocation et quotas ; Nmap réel dans un labo autorisé | Résultats reproductibles, preuves et limites publiées dans le dépôt ; aucune affirmation de production sans mesure |

P1.4 commence par un worker isolé dont les ressources, les sorties réseau et
les descendants sont contrôlés par le système. Le test de crash de P1.3 montre
pourquoi la perte du superviseur ne suffit pas à prouver l'arrêt de son outil.

Le choix éventuel d'un système de workflows vient après ces contrats et un
essai mesuré. Ce lot ne présume ni file distribuée ni framework particulier.
