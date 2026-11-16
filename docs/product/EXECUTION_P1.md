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

Implémenté et validé localement :

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

Après une panne, `pending` et `running` signifient **dernier état persisté**,
pas preuve qu'un processus existe encore. Ouvrir un gestionnaire ne les relance
pas et ne reprend pas leur propriété ; `cancel()` ne pilote que ses jobs locaux.
Une écriture terminale refusée peut laisser `running` sur disque et une erreur
de persistance dans le gestionnaire courant. P1.3 doit réconcilier cet écart.
Les limites de capacité restent locales à un gestionnaire ; aucune garantie
d'exclusion entre plusieurs gestionnaires n'est livrée dans P1.2.

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
et CI distante non exécutée pour ce lot.

## Livraisons suivantes

| Lot | Travail | Critères de sortie |
| --- | --- | --- |
| P1.3 — Réconciliation | Identifier les jobs interrompus ; gérer la propriété d'un job et empêcher les doubles lancements ; revérifier le mandat avant toute reprise | Crash avant/après lancement testé ; aucun ancien PID réutilisé aveuglément ; aucune action relancée sans décision explicite de reprise |
| P1.4 — Isolation | Exécuter dans un worker séparé ; appliquer les quotas CPU, mémoire, processus et disque et les restrictions réseau | Dépassements arrêtés par le système ; sorties hors périmètre bloquées ; nettoyage des descendants vérifié |
| P1.5 — Qualification | Scénarios de saturation, crash, reprise, révocation et quotas ; Nmap réel dans un labo autorisé | Résultats reproductibles, preuves et limites publiées dans le dépôt ; aucune affirmation de production sans mesure |

P1.3 commence par la propriété et la réconciliation des jobs historiques.
Un redémarrage doit distinguer un job en attente d'un job dont l'exécution
est incertaine. La reprise d'une mission ne signifie pas rejouer
automatiquement toutes ses actions.

Le choix éventuel d'un système de workflows vient après ces contrats et un
essai mesuré. Ce lot ne présume ni file distribuée ni framework particulier.
