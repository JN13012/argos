# M3.1 — Fondations de revue de mission

L'[audit préalable](DECISION_ENGINE_AUDIT.md), livré dans `97f59d8`, décrit
le socle de départ. Les interfaces de ce lot servent à consulter des archives
et à consigner des décisions humaines. Les autorisations relèvent du Policy Engine.
Les composants B à E forment la revue consultative. L'[analyste local
M3.2](M32_LOCAL_LLM_ANALYST.md) réutilise leur contexte. Le moteur
décisionnel autonome reste non implémenté.

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

## E — Mission Review & Context Engine

```bash
python -m argos review summary --db BASE_PRIVEE --mission-id UUID_MISSION
python -m argos review summary --db BASE_PRIVEE --mission-id UUID_MISSION \
  --max-context-bytes 4096 --journal JOURNAL_PRIVE --expected-head EMPREINTE
```

`mission_review(database, mission_id, *, max_context_bytes=32768,`
`journal=None, expected_head=None)` relit le snapshot B et inclut la
version de l'inventaire C et les identifiants de ses interfaces hors ligne.
Le document JSON `mission-review-context-v1` renvoie des entrées typées
et l'empreinte du snapshot vérifié.

- `fact` qualifie une réponse HTTP archivée ou une observation rapportée
  par une projection. Un statut HTTP signifie qu'une réponse a été
  observée. Une opération métier ou un effet demande des preuves propres.
- `inference` désigne une association déduite par la cartographie ou le
  fingerprinting. L'état de confiance du fingerprint reste visible.
- `unknown` couvre les données absentes ou incertaines, notamment les
  transactions sans statut vérifié, les projections manquantes et les
  éléments non résolus. La couverture reste partielle.
- `contradiction` signale une assertion incompatible dans une projection.
  L'identifiant natif de l'observation permet de retrouver ses valeurs dans
  le snapshot privé. Des projections historiques distinctes restent distinctes.

Chaque entrée renvoie à un reçu, à une projection vérifiée ou au snapshot
pour un écart de couverture. Le contexte utilise des agrégats, des codes
contrôlés et des références SHA-256. Il exclut les hôtes, chemins, paramètres,
versions brutes, contenus de cible et textes d'opérateur. Les identifiants,
empreintes, statuts et technologies identifiées restent des métadonnées
privées. La commande ne transmet aucune donnée à un fournisseur.

Le plafond de 4 096 à 131 072 octets s'applique au JSON canonique UTF-8 du
champ `context`, hors enveloppe CLI. `size` donne la taille réelle, le
plafond et le nombre d'entrées. Les contradictions et incertitudes passent
en premier pour la revue. Les comptes d'entrées omises sont explicites par état.
Ces mesures ne dépendent d'aucun tokenizer.

Avec `--journal`, la commande vérifie D en lecture seule et expose la tête,
le nombre de décisions de la mission et le nombre lié au snapshot courant,
hors du contexte. L'opérateur consulte les décisions avec `journal-show`
et consigne une décision explicite avec `journal-append`. Les références
`http_receipt` et `recon_projection` de la revue fournissent les identifiants
du journal. Pour un manque d'observation, l'opérateur peut laisser la liste
des sources vide et renseigner le contexte.

### Qualification E

Les archives contextuelles r1 de M2.7.1 ont été relues avec l'ouverture de
sockets, la résolution DNS et les sous-processus bloqués. Les bases SQLite
sont restées identiques octet pour octet. Les trois empreintes de contexte
coïncident sous Python 3.12.15 et 3.14.6.

| Archive | Snapshot canonique (octets) | Contexte par défaut (octets) | Faits / inférences / inconnues | Contexte plafonné à 4 096 octets |
| --- | ---: | ---: | ---: | ---: |
| Juice Shop | 1 144 020 | 22 899 | 70 / 16 / 8 | 4 096 |
| crAPI | 589 942 | 19 344 | 52 / 17 / 8 | 4 082 |
| DVWA | 331 832 | 19 926 | 57 / 16 / 7 | 4 074 |

Le plafond par défaut conserve toutes les entrées de ces trois revues. Les
comptes décrivent les entrées du contexte, qui peuvent agréger plusieurs
observations par projection. Ces archives ne contiennent aucune contradiction
signalée. Les cinq tests de `tests/test_mission_review.py` vérifient notamment
une contradiction synthétique, l'absence de données, la conservation des
références, les omissions sous plafond, la vérification du journal et le
refus d'un reçu altéré.

## Commandes de validation

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
python -m pytest -q tests/test_mission_snapshot.py tests/test_capability_registry.py \
  tests/test_operator_journal.py tests/test_mission_review.py -o faulthandler_timeout=15
python -m pytest -q -o faulthandler_timeout=30
git diff --check
```

Les cinq tests E réussissent sous Python 3.12.15 et 3.14.6. La suite régulière
compte 1 208 réussites et 121 tests ignorés par interpréteur, avec les essais
hôte optionnels désactivés. Ruff, Pyright, les liens locaux et la vérification
des espaces passent.
