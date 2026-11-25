# M3.1 — Fondations de revue de mission

L'[audit préalable](DECISION_ENGINE_AUDIT.md), livré dans `97f59d8`, décrit
le socle de départ. Les interfaces de ce lot servent à consulter des archives
et à consigner des décisions humaines. Les autorisations relèvent du Policy Engine.

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
  le run réseau associé, avec son propre identifiant de mission. Une mission
  réseau inclut aussi les projections rattachées à ses runs seuls.
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
La copie temporaire requiert un espace disque de l'ordre de la taille de la
base source.

Les fixtures `tests/test_mission_snapshot.py` couvrent le déterminisme, la
lecture après révocation, les contradictions, les budgets, la confidentialité
des valeurs de query, l'isolation entre missions et le rejet d'un reçu altéré.
La relecture des trois bases privées M2.7.1 (crAPI, DVWA et Juice Shop)
couvre cinq projections par mission et respectivement 38, 37 et 58
transactions HTTP. Les empreintes des trois snapshots coïncident sous
Python 3.12 et 3.14.

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

## D — Decision Journal

```bash
python -m argos review journal-append --db BASE_PRIVEE --mission-id UUID_MISSION \
  --journal JOURNAL_PRIVE --input DECISION.json
python -m argos review journal-show --journal JOURNAL_PRIVE --mission-id UUID_MISSION
python -m argos review journal-show --journal JOURNAL_PRIVE --expected-head EMPREINTE
```

L'API expose `record_decision(database, journal, mission_id, supplied)`
et `read_journal(journal, mission_id=None, expected_head=None)`, avec les
filtres transmis par mot-clé. La base du journal est distincte de la base
de mission. Le CLI exige des fichiers et répertoires privés. Les décisions
saisies restent dans ces fichiers et les sorties JSON du CLI.

Le fichier d'entrée est un objet JSON de 64 Kio au plus. L'opérateur fournit
un UUID stable pour la décision, son identifiant, les textes de décision,
de motivation et de contexte, l'empreinte du snapshot examiné et la liste
explicite des références. L'exemple utilise des identifiants et une empreinte
fictifs à remplacer par les valeurs de l'archive.

```json
{
  "id": "10000000-0000-4000-8000-000000000001",
  "snapshot_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "operator": "revue-interne",
  "decision": "Indiquer une couverture partielle dans le rapport.",
  "rationale": "Le plan archivé se limite aux observations déjà vérifiées.",
  "context": "Revue du rapport avant sa remise.",
  "sources": [{"kind": "recon_projection", "id": "10000000-0000-4000-8000-000000000002"}]
}
```

Les références acceptent un UUID de reçu HTTP (`http_receipt`), un UUID
de job réseau muni d'un reçu (`network_receipt`) ou un UUID de projection
(`recon_projection`). La liste peut être vide pour consigner un manque de
données. À l'ajout, le snapshot est recalculé. Chaque référence doit y
figurer et reçoit son empreinte vérifiée. Le journal enregistre également
la version du snapshot, le contexte de mission et l'horodatage UTC.
L'identité déclarée par l'opérateur est rattachée à l'enregistrement
sans authentification ni signature de cette identité.

Chaque enregistrement `operator-decision-journal-v1` porte un numéro
de séquence et l'empreinte de son prédécesseur. L'écriture du record et
de la tête se fait dans une transaction SQLite. Une nouvelle soumission
du même UUID avec la même décision et la même mission retourne le record
existant. Si son contenu diffère, le journal refuse l'ajout. La lecture
vérifie toute la chaîne avant d'appliquer le filtre de mission. Pour
détecter une restauration ancienne ou une réécriture intégrale cohérente,
conserver le SHA-256 de tête dans un emplacement indépendant et fournir
cette valeur à `--expected-head`. Une relecture du contenu complet de la
mission à cet instant exige de conserver le snapshot ou l'archive source.

Le journal conserve les textes fournis. Ses entrées ont un usage de revue
et ne sont reliées à aucun exécuteur ni au journal de politique.
Les tests de `tests/test_operator_journal.py` couvrent cinq cas, dont la
liaison au reçu, le rejet d'un contexte périmé et de sources étrangères,
l'intégrité après modification ou suppression, et la répétition concurrente.
Un journal temporaire a également relié une décision de fixture à une
projection réseau et à son reçu dans l'archive M2.7.1 de DVWA.

## Commandes de validation

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
python -m pytest -q tests/test_mission_snapshot.py tests/test_capability_registry.py \
  tests/test_operator_journal.py -o faulthandler_timeout=15
python -m pytest -q -o faulthandler_timeout=30
git diff --check
```

Sous Python 3.12.15 et 3.14.6, 11 tests ciblés réussissent par interpréteur.
La suite régulière compte 1 203 réussites et 121 tests ignorés par
interpréteur, avec les essais hôte optionnels désactivés. La qualification
des composants utilise des archives SQLite locales et des fixtures
synthétiques.
