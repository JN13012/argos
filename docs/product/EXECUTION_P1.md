# P1 — Exécution durable et isolée

Suivi du 16 novembre 2026. Ce lot prépare le runtime des missions autonomes.
Il ne connecte aucun agent et n'ajoute aucun outil offensif.

## P1.1 — Capacité et cache terminal

Implémenté et validé localement :

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

Après éviction, `get()` et `result()` retournent `None` ;
`verified_evidence()` peut toujours charger les preuves persistées.
`JobAudit.list_for_job()` donne l'historique persistant par identifiant.
Les consommateurs doivent tenir compte de cette rétention finie : un résultat
en mémoire n'est pas un stockage durable. Une phase adaptative dont le résultat
a été évincé échoue explicitement ; la lecture durable des résultats relève de
P1.2. Aucune suppression des preuves ou de l'audit sur disque n'est introduite.

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
sur l'ensemble du Python. La CI distante n'a pas été exécutée pour ce lot.

## Livraisons suivantes

| Lot | Travail | Critères de sortie |
| --- | --- | --- |
| P1.2 — Persistance | Enregistrer la demande et le plan, les états et les liens vers les preuves ; ajouter les lectures durables ; gérer les erreurs d'écriture | États et résultats retrouvés depuis un nouveau gestionnaire ; état terminal cohérent avec les preuves ; tests de panne du stockage |
| P1.3 — Réconciliation | Identifier les jobs interrompus ; gérer la propriété d'un job et empêcher les doubles lancements ; revérifier le mandat avant toute reprise | Crash avant/après lancement testé ; aucun ancien PID réutilisé aveuglément ; aucune action relancée sans décision explicite de reprise |
| P1.4 — Isolation | Exécuter dans un worker séparé ; appliquer les quotas CPU, mémoire, processus et disque et les restrictions réseau | Dépassements arrêtés par le système ; sorties hors périmètre bloquées ; nettoyage des descendants vérifié |
| P1.5 — Qualification | Scénarios de saturation, crash, reprise, révocation et quotas ; Nmap réel dans un labo autorisé | Résultats reproductibles, preuves et limites publiées dans le dépôt ; aucune affirmation de production sans mesure |

P1.2 commence par le schéma persistant et ses invariants. Une demande acceptée
doit être enregistrée avant lancement. Un redémarrage doit distinguer un job
en attente d'un job dont l'exécution est incertaine. La reprise d'une mission
ne signifie pas rejouer automatiquement toutes ses actions.

Le choix éventuel d'un système de workflows vient après ces contrats et un
essai mesuré. Ce lot ne présume ni file distribuée ni framework particulier.
