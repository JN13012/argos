# M3.1 — Fondations de revue de mission

L'[audit préalable](DECISION_ENGINE_AUDIT.md) décrit le socle au commit
`97f59d8`. Les interfaces de ce lot servent à consulter des archives et à
consigner des décisions humaines. Les autorisations relèvent du Policy Engine.

## B — Mission State Snapshot

```bash
python -m argos review snapshot --db BASE_PRIVEE --mission-id UUID_MISSION
```

L'API `mission_snapshot(database, mission_id)` et le CLI renvoient
`{"snapshot": ..., "sha256": ...}`. L'empreinte couvre le JSON canonique
`mission-state-snapshot-v1`. Les résultats gardent les identifiants natifs
et restent reproductibles à partir du même état SQLite. Une copie temporaire
privée fige les lectures entre magasins. La base d'origine est ouverte en
lecture seule.

- L'état et l'expiration sont les valeurs enregistrées dans la mission.
  La lecture fonctionne après révocation. L'empreinte de configuration
  relie les transactions HTTP à leur configuration archivée.
- Les transactions HTTP conservent leur méthode, chemin sans query, état et
  reçu expurgé lorsqu'il existe. Les projections réseau, fingerprinting,
  cartographie et couverture contextuelle passent par les lecteurs du harness.
  Les liens déjà vérifiés par une carte ou un fingerprint permettent d'inclure
  le run réseau associé, avec son propre identifiant de mission.
- Les contradictions gardent leurs deux niveaux d'identité, run et observation.
  Les valeurs et preuves restent dans leurs projections. Les écarts entre
  projections de dates différentes restent consultables comme historique.
- Les budgets sont historiques. Le snapshot expose les plafonds de
  configuration, tickets HTTP et navigateur, octets des reçus/réservations HTTP
  et durée au dernier pointage persisté. Les réservations contextuelles et
  plafonds réseau restent rattachés à leur run, dans leurs unités d'origine.
  Le compteur d'octets HTTP ne couvre pas la totalité du stockage de preuves
  de la mission. Une mesure absente vaut `null` ou apparaît dans les limites.
- La couverture est explicitement partielle. Les archives recon hors des quatre
  projections prises en charge sont comptées parmi les omissions. Les documents
  et plans contextualisés peuvent être vérifiés comme sources de ces projections.
  Les captures et navigations ne sont pas restituées en intégralité. Les cartes,
  chemins et preuves expurgées restent des données privées.

Une vérification de lecteur en échec interrompt la restitution. L'empreinte
est une référence de cohérence, sans signature ni garantie d'authenticité
en cas de réécriture intégrale des données. Le CLI renvoie 1 pour une erreur
de stockage ou d'intégrité, et 2 pour un argument ou une mission inconnue.

Les fixtures `tests/test_mission_snapshot.py` couvrent le déterminisme, la
lecture après révocation, les contradictions, les budgets, la confidentialité
des valeurs de query et le rejet d'un reçu altéré. La relecture des trois
bases privées M2.7.1 (crAPI, DVWA et Juice Shop) couvre cinq projections par
mission et respectivement 38, 37 et 58 transactions HTTP. Les empreintes
des trois snapshots coïncident sous Python 3.12 et 3.14.

## C — Capability Registry

```bash
python -m argos review capabilities
python -m argos review capabilities --registry REGISTRE_ADMIN.toml
```

L'API `capability_registry(registry=None)` renvoie l'inventaire
`capability-registry-v1` trié par identifiant. Chaque fiche décrit le mode,
les prérequis, les entrées, les sorties et les restrictions de la capacité.
Les entrées et sorties sont des descriptions, sans commande ni adaptateur
d'exécution.

Sans registre explicite, l'état des outils est `not_checked`. Avec un
`ToolRegistry` chargé par l'appelant (ou `--registry` au CLI), l'identité
des dépendances est vérifiée par le registre existant. Les états exposés
sont `identity_verified`, `missing` et `invalid`. Aucun chemin local de
binaire ni aucune épingle d'installation ne figure dans la sortie.
`local_reader` signale une interface de lecture livrée. L'environnement
d'exécution et les autorisations de mission ne sont pas testés.

Les deux tests de `tests/test_capability_registry.py` couvrent le résultat
déterministe sans registre et les états d'identité sur un registre synthétique.
La création d'un sous-processus y est interdite par la fixture.
