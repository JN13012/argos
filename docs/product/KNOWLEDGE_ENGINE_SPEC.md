# Knowledge Engine — spécification canonique

Le Knowledge Engine fournit des connaissances documentaires locales aux
différentes spécialisations d'Argos. Les connaissances documentaires, les
observations mémorisées et les preuves de mission ont des identités et des
cycles de vie distincts. Le composant se trouve sous `argos/backend/knowledge/`
et dépend uniquement de la bibliothèque standard et du résolveur de données.

## Décisions et statut

| Lots | Décisions consolidées | Statut |
| --- | --- | --- |
| M3.5-A à C | Dix domaines extensibles et tags multidimensionnels. Collections globale, organisation, utilisateur, mission et connaissances acquises. Sources officielles prioritaires après validation, acquisition locale progressive et import Obsidian privé sur sélection explicite. | Taxonomie, catalogues locaux et frontières de stockage implémentés en M3.5.1. Priorité de recherche, Obsidian et acquisition publique conçus. |
| M3.5-C.1 | Données privées sous `ARGOS_DATA_HOME/knowledge/`. Ressources redistribuables validées sous `resources/`. | Résolution et stockage privé qualifiés localement. Voir le [lot stockage](M351_DATA_ARCHITECTURE.md). |
| M3.5-D | Version par contenu et provenance, approbation explicite, base SQLite par frontière d'accès. Normalisation et index FTS5 comme projections dérivées. Index vectoriel interchangeable. | Sources, originaux et versions implémentés en M3.5.1. Normalisation et fragments qualifiés en M3.5.2, SQL exact et FTS5 en M3.5.3. Cache et recherche NumPy exacts qualifiés localement en M3.5.4. |
| M3.5-E | NumPy exact, EmbeddingGemma 768 sous conditions Gemma et Qwen3 512 en alternative. Dense prioritaire et FTS5 en secours pour le futur pilote. Recherche exacte SQL qualifiée sur fixtures en M3.5.3. Lots de 16 à revalider, cache versionné, indexation incrémentale et préfiltrage obligatoire. RRF et reranker reportés. | Mesures de banc consolidées, moteur NumPy qualifié en M3.5.4, choix du pilote provisoires. Voir le [rapport M3.5-E](M35_RETRIEVAL_BENCHMARK.md). |
| M3.5-F à H | Contexte consultatif versionné et borné, benchmark comparatif indépendant, maintenance avec retrait et reconstruction. | Conception ci-dessous. Les contrats de lecture bornent l'accès des futurs consommateurs aux documents publiés. |

## Fondations M3.5.1

### Portée et stockage

Une instance `KnowledgeStore(Collection(...))` est liée à un UID Unix effectif
et à une collection explicite. Le constructeur ne crée aucun fichier.
`initialize()` initialise la seule base demandée. Le chemin forme
`ARGOS_DATA_HOME/knowledge/uid-UID/COLLECTION/knowledge.sqlite3`, avec
`global`, `user`, `mission-UUID`, `acquired` ou `acquired-UUID` comme dossier.
La collection globale permet à l'opérateur local de constituer ses références
communes sous son UID. La catégorie organisation accepte un UUID dans son
contrat et son ouverture est refusée pendant ce lot. Le partage entre comptes
dépend d'une identité et d'une adhésion organisationnelle vérifiables.

Un appelant de confiance choisit la mission avant d'ouvrir son magasin. Deux
processus sous le même UID partagent le même domaine de confiance. Les
répertoires privés, bases et fichiers auxiliaires sont vérifiés avant
l'ouverture. Les liens symboliques, les bases avec plusieurs liens et les
ancêtres modifiables par d'autres comptes sans protection sont refusés.
L'identité UID/type/portée enregistrée dans la base détecte une copie déplacée
vers une autre collection. Voir l'[ADR stockage documentaire](../architecture/adr/0006-knowledge-storage.md).

| Élément SQLite v1 | Rôle |
| --- | --- |
| `collection` | Identité du fichier et de sa portée. `application_id` et `user_version` identifient le schéma. |
| `domain` | Dix domaines préchargés par collection et extensions locales explicites. |
| `source` | Éditeur, origine déclarée, droits d'usage, marqueur officiel déclaré et dates d'enregistrement, d'approbation et de retrait. |
| `document` | Identité unique par source et date de retrait logique. |
| `original` | Octets originaux exacts, de 1 à 16 Mio, uniques par SHA-256 dans la collection. |
| `version` | Identité dérivée du document, du SHA-256 original et des métadonnées canoniques. Inclut titre, type de média, origine, langue, version déclarée, tags et dates. Une contrainte garantit une seule version approuvée non remplacée par document. |

Les domaines initiaux sont `web-api`, `application-security`,
`network-infrastructure`, `identity-access`, `cloud`, `osint`, `defense`,
`governance-risk-compliance`, `ai-security` et `software-supply-chain`.
Les identifiants stables emploient lettres ASCII minuscules, chiffres,
tiret et souligné. La dimension `domain` référence le catalogue de la
collection. Les autres dimensions restent extensibles. Les tags identiques
sont regroupés sans modifier la provenance ni les droits.

### Interfaces et cycle de vie

- `KnowledgeStore.initialize()`, `domains()` et `register_domain()` gèrent
  le stockage et son vocabulaire.
- `KnowledgeSourceRegistry`, accessible par `store.sources`, expose
  `register`, `get`, `list`, `approve` et `withdraw`. Soumettre les mêmes
  métadonnées est idempotent. Un changement d'identité éditoriale demande
  une nouvelle source déclarée.
- `import_document` accepte des octets fournis par l'appelant et des
  métadonnées structurées. L'import crée une version en attente. Importer
  à nouveau le même contenu avec les mêmes métadonnées renvoie la même
  version. Des métadonnées ou origines différentes créent des versions
  distinctes qui peuvent référencer le même original.
- `approve_version` vérifie d'abord la source, la version et l'original,
  puis remplace la version courante dans une transaction. Une approbation
  répétée est idempotente. Le retrait d'une source ou d'un document le
  masque dès la lecture publiée suivante. Les retraits sont terminaux
  dans ce lot. Après un arrêt brutal, `initialize()` ouvre la base en
  écriture pour laisser SQLite reprendre son journal.
- `DocumentReader` lit uniquement la version courante publiée, par
  `current` et `read_original`. L'opérateur local conserve une interface
  distincte d'inspection avec `versions`, `inspect_version` et
  `inspect_original`, y compris après retrait logique. `KnowledgeRetriever`
  définit le futur contrat de recherche de passages dans une collection
  déjà autorisée. Sa réalisation est reportée.

Exemple local depuis le clone. Le magasin reçoit des octets en mémoire.
Les références d'origine et le document sont traités comme des données.
Les octets importés ne déclenchent aucune ouverture de chemin ni de réseau.

```python
from argos.backend.knowledge import (
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeStore,
    Source,
)

store = KnowledgeStore(Collection(CollectionKind.USER))
store.initialize()
store.sources.register(Source("fixture", "Éditeur local", "notes:fixture", "CC0"))
store.sources.approve("fixture")
document = DocumentRef("fixture", "guide")
version = store.import_document(
    document,
    DocumentMetadata("Guide", "text/markdown", "notes:guide", language="fr"),
    b"# Guide\n",
)
approved = store.approve_version(document, version.id)
assert store.read_original(document, approved.id) == b"# Guide\n"
```

Les approbations sont des décisions de l'opérateur local. Les SHA-256
vérifient l'identité des octets et des métadonnées, avec la même limite
que les autres stores locaux face à une réécriture complète par leur
propriétaire. Le retrait est logique et les BLOB demeurent dans la base
privée. Les positions des passages, la recherche indexée, la génération
et l'API multi-utilisateur ne sont pas livrées en M3.5.1.

### Qualification locale M3.5.1

Les 21 tests ciblés passent sous Python 3.12.15 et 3.14.6. Les fixtures
vérifient l'initialisation depuis un autre répertoire, les permissions,
les frontières UID/mission, le registre, le retrait, la déduplication
concurrente, l'intégrité des originaux et la reprise après arrêt du
processus avant commit. L'exemple ci-dessus a été rejoué avec une racine
personnalisée sur les deux interpréteurs.

```bash
python -m pytest -q tests/test_knowledge_storage.py tests/test_knowledge_documents.py
python -m pytest -q -o faulthandler_timeout=30
```

La suite régulière compte 1 297 réussites et 122 ignorés sous chaque
interpréteur. Ruff, formatage, Pyright, liens documentaires et contrôle
Git passent. Les essais hôte optionnels ne font pas partie de cette
qualification. La validation UID porte sur les permissions et un
changement d'UID simulé, sans qualification de comptes organisationnels.

## M3.5.2 — Ingestion, normalisation et fragments

### Contrats et formats

`KnowledgeStore.ingest_file(path, document, metadata, config)` ouvre un
fichier local explicitement désigné par l'opérateur. Les chemins relatifs sont
résolus depuis le répertoire courant. Chaque composant est ouvert sans suivre
de lien symbolique et les fichiers spéciaux ainsi que les composants `..`
sont refusés. L'extension est comparée au type de média déclaré. L'adaptateur
`ingest_bytes(document, metadata, original, config)` accepte des octets déjà
sélectionnés, avec les mêmes contrôles de normalisation. Le contrat brut de
M3.5.1, `import_document`, continue de fonctionner pour ses appelants.

- Markdown (`.md`, `.markdown`) et texte (`.txt`) utilisent UTF-8 strict
  avec BOM facultatif et fins de ligne normalisées en LF. Les blocs Markdown
  repèrent les titres ATX et Setext, les paragraphes, listes, blocs de code
  et l'en-tête initial délimité par `---`. Les délimitations et le texte sont
  conservés. Les repères vont de la première à la dernière ligne de la
  citation sur l'original, à partir de 1. La reconnaissance des blocs est
  volontairement limitée pour les constructions Markdown imbriquées. Un
  bloc de code balisé sans fermeture est refusé.
- JSON (`.json`) conserve objets, tableaux et valeurs dans une projection
  textuelle déterministe. Les objets sont ordonnés par clé, les tableaux
  conservent leur ordre et les nombres conservent leur graphie. Le JSON
  Pointer cite la valeur ou le conteneur du document original, avec `""` pour
  la racine et échappement de `~` et `/`. Les doublons de clés, constantes
  numériques non standard et données malformées sont refusés.
- Les liens, transclusions Obsidian, macros MDN, code et instructions
  documentaires sont stockés comme texte inerte. Les métadonnées
  d'autorisation viennent de l'opérateur. L'import de coffre et la
  résolution de pièces jointes restent reportés.

Les plafonds sont de 16 Mio à l'entrée et de 32 Mio pour l'enveloppe
normalisée. Markdown et TXT sont limités à 200 000 lignes, 65 536 caractères
par ligne et 20 000 blocs. JSON est limité à 48 niveaux de conteneurs,
20 000 blocs et 2 048 caractères par pointeur. Les entrées dépassant une
borne sont refusées avant commit.

### Découpage et stockage

`ChunkConfig` exprime une taille de 64 à 16 384 caractères Unicode et un
chevauchement de zéro à un quart de la taille. Le découpage fixe utilise
des fenêtres, le structurel privilégie les sections et fins de blocs, et
le récursif essaie ensuite les fins de lignes et les espaces. Un bloc
trop long peut être coupé dans les trois modes. Le chevauchement reste
dans une section pour les deux modes qui respectent les sections et
chaque projection est plafonnée à 50 000 fenêtres. Le réglage CLI par
défaut est fixe, 1 024 caractères et zéro chevauchement. Il reste
provisoire jusqu'à une qualification au niveau passage.

`initialize()` et `argos knowledge init` migrent chaque base v1 ouverte
vers SQLite v2 en une transaction. Les six tables v1 et leur cycle de vie
restent en place. La migration laisse les versions historiques intactes.
Rejouer explicitement l'ingestion des octets et métadonnées d'une version
ancienne ajoute sa projection sans modifier son identité ni son statut.

| Ajout SQLite v2 | Rôle |
| --- | --- |
| `normalized` | Texte et carte de blocs encodés ensemble, uniques par SHA-256 dans la collection. |
| `normalization` | Correspondance entre SHA-256 original, média, version `normalize-v1` et SHA-256 normalisé. |
| `chunk_set` | Projection partagée par SHA-256 normalisé et identité `chunk-v1:STRATÉGIE:TAILLE:CHEVAUCHEMENT`. |
| `fragment` | Ordinal, offsets de début inclus et de fin exclus, et SHA-256 du texte. La lecture reconstruit texte, sections et repères depuis la carte des blocs. |
| `version_projection` | Association d'une version documentaire à chacun de ses jeux de fragments explicites. |

Une ingestion identique réutilise la normalisation et le jeu de fragments.
Des métadonnées modifiées conservent la provenance propre à la nouvelle
version et partagent les projections inchangées. Un nouveau réglage
redécoupe le contenu normalisé. Le SHA-256 normalisé inclut les repères,
ce qui prévient le partage entre documents dont les mêmes extraits citent
des positions distinctes. Les données dédupliquées restent dans leur
collection. Les originaux, versions et projections sont enregistrés dans la
même transaction d'ingestion. La publication reste explicite. Le retrait logique masque
immédiatement les lectures publiées et conserve les données opérateur.
L'identité version/normaliseur/chunker/ordinal permet aux futurs index de
référencer ces fragments et de reconstruire leurs projections.

`inspect_projection`, `inspect_normalized` et `inspect_fragments` sont
des accès opérateur. `read_normalized` et `read_fragments` vérifient la
source, la version courante et le retrait dans la même lecture SQLite.
`read_fragments` et `inspect_fragments` paginent par ordinal et renvoient
des `DocumentFragment` avec version, SHA-256, section et un ou plusieurs
repères. La vérification d'empreinte s'applique au contenu restitué.

### Utilisation locale

```bash
export ARGOS_DATA_HOME=/chemin/prive/argos-data
python -m argos knowledge init
python -m argos knowledge source-register local --publisher Manuel \
  --origin notes:local --rights Privé
python -m argos knowledge import guide.md local guide --title Guide \
  --origin notes:guide --tag domain=web-api
python -m argos knowledge versions local guide
python -m argos knowledge inspect local guide "$VERSION" --normalized
python -m argos knowledge fragments local guide "$VERSION" --retained --limit 10
python -m argos knowledge source-approve local
python -m argos knowledge approve local guide "$VERSION"
python -m argos knowledge show local guide --normalized
python -m argos knowledge fragments local guide "$VERSION" --limit 10
python -m argos knowledge withdraw local guide
```

`VERSION` est le champ JSON `version.id` renvoyé par `import`. Pour
une autre stratégie, donner les mêmes `--strategy`, `--size` et
`--overlap` à `import` et à `fragments`. La collection par défaut est
`user`. Pour une mission, ajouter `--collection mission --scope-id UUID`
avant la sous-commande. Le CLI renvoie du JSON et demande un `init`
explicite pour créer ou migrer une collection.

### Qualification locale

Les tests couvrent les trois formats et stratégies, les bornes, les repères,
la migration atomique, la reprise après arrêt du processus, les imports
concurrents, la déduplication, le cycle d'approbation/retrait et le
cloisonnement. Les formats TXT et JSON sont qualifiés sur fixtures.
Les 52 tests documentaires passent sous Python 3.12.15 et 3.14.6. La
suite régulière compte 1 328 réussites et 122 ignorés sur chaque version.
Ruff, le formatage, Pyright et `git diff --check` passent également.

Le [probe d'ingestion](../../benchmarks/retrieval/ingestion_probe.py) rejoue
les 38 fichiers MDN locaux de M3.5-E et vérifie leurs empreintes et celle
de la licence épinglée. Exécuter cette commande par stratégie et
interpréteur depuis le clone. Le corpus est lu en place et la base
temporaire est propre à chaque passage.

```bash
python -m benchmarks.retrieval.ingestion_probe --strategy fixed
python -m benchmarks.retrieval.ingestion_probe --strategy structural
python -m benchmarks.retrieval.ingestion_probe --strategy recursive
```

Mesures locales Linux, SQLite 3.53.1, 290 669 octets d'originaux, taille
1 024, chevauchement zéro, un passage par couple et une réimportation
immédiate. Le chronomètre englobe lecture, traitement et transactions
d'ingestion. Le RSS est le pic du processus complet jusqu'au rejeu. Le
volume est celui du fichier SQLite après commit. Les empreintes combinées
des fragments stockés sont identiques entre interpréteurs pour chaque mode.
Les six relevés JSON de cet essai restent dans le répertoire local
`data/qualification/m352-ingestion/`.

| Stratégie | Fragments | SQLite (octets) | Import / rejeu 3.12.15 (ms) | RSS 3.12.15 (Kio) | Import / rejeu 3.14.6 (ms) | RSS 3.14.6 (Kio) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fixe | 299 | 1 069 056 | 220 / 117 | 24 416 | 206 / 92 | 26 040 |
| Structurel | 564 | 1 118 208 | 240 / 100 | 24 340 | 201 / 113 | 26 144 |
| Récursif | 567 | 1 114 112 | 225 / 118 | 24 204 | 227 / 96 | 26 164 |

Les écarts de nombre de fragments par rapport à M3.5-E reflètent notamment
la conservation du front matter, les frontières de blocs et l'absence de
déduplication destructive des occurrences. Ces mesures décrivent
l'ingestion sur le corpus disponible. La qualité de recherche, les budgets
sous charge et la rétention physique restent à qualifier.

## M3.5.3 — Recherche SQL exacte et FTS5

### Stockage et cycle de vie

`argos knowledge init` applique la migration v3 et indexe les versions
courantes approuvées dont la source reste approuvée et qui possèdent une
projection. Les versions brutes M3.5.1 deviennent cherchables après rejeu
explicite de leur ingestion normalisée. Une seule projection par version
alimente la recherche. Le moteur préfère le découpage fixe par défaut quand
il existe, puis trie les autres identités de chunker lexicalement.

| Ajout SQLite v3 | Rôle |
| --- | --- |
| `search_document` et `search_tag` | Projection courante, source, identifiant documentaire et filtres. |
| `search_fragment` et `search_fts` | Titre et corps des fragments publiés et index FTS5 à contenu externe. |
| `search_reference` | Clés exactes et priorité documentaire, par occurrence. |

L'approbation, le remplacement et le retrait synchronisent les index dans
la transaction du cycle de vie. Un retrait de document ou de source enlève
les entrées FTS5 et SQL et conserve les originaux pour l'inspection. Le
rejeu à projection inchangée évite la réindexation. La reconstruction
repart des projections déjà conservées, sans rouvrir les fichiers sources.
La vérification contrôle SQLite, l'index FTS5 contre son contenu externe,
les tags, les clés exactes et le corpus effectivement publié.

### Contrat et comportement

`SQLiteKnowledgeRetriever` implémente `KnowledgeRetriever.retrieve` et
expose `exact`, `resolve`, `index_status`, `verify_index` et
`rebuild_index`. Le constructeur reçoit une collection et la liste autorisée
fournie par l'appelant de confiance. Chaque opération contrôle la collection
avant ouverture. Les permissions Unix et l'identité de la base continuent
de s'appliquer. La CLI opère sur la collection explicitement choisie par
l'opérateur local sous son UID.

Un `Passage` conserve le document, la version, le texte, la provenance
source et documentaire, la méthode, le score, le `FragmentRef` et ses
repères de citation. Le statut `current` décrit l'état de publication. La
date ou l'applicabilité métier de l'information reste à évaluer. `resolve`
revérifie la portée, la version courante, le retrait et l'empreinte.
Une citation cesse d'être résoluble après remplacement ou retrait de sa
version, ou après un changement de projection active.

- **Lexical.** BM25 avec poids titre/corps configurables, 2/1 par défaut.
  Les mots littéraux et les expressions entre guillemets sont combinés
  par OU. La tokenisation Unicode rend la recherche insensible aux accents
  et traite la ponctuation technique comme séparateur. Les égalités sont
  triées par source, identifiant documentaire et ordinal.
- **Exact.** Clés pour CVE, CWE, RFC et des références ISO/IEC, IEC, IEEE,
  NIST SP, OWASP ASVS et WSTG. La comparaison ignore la casse des familles
  officielles et préserve les numéros, parties, années et révisions. Un
  identifiant documentaire local est comparé dans sa graphie canonique.
  `doc:source/identifiant` sélectionne un document d'une source précise.
  L'identité du document précède les mentions dans le titre puis le corps.
  Les homonymes de sources distinctes conservent chacun leur provenance.
  Une mention doit tenir dans un fragment. Le contexte de coupure empêche
  d'indexer son préfixe comme une référence entière.
- **Filtres et bornes.** Source et domaine sont des filtres alternatifs au
  sein de leur famille, les tags sont cumulatifs et la version déclarée
  est comparée exactement. Ces filtres agissent avant la limite de résultats.
  BM25 utilise les statistiques de la collection autorisée en entier. Les
  requêtes lexicales sont plafonnées à 1 024 octets et 32 termes ou
  expressions, les requêtes exactes à 256 octets. La récupération traite
  jusqu'à 500 candidats et rend au plus 100 passages, dans un budget JSON
  de 128 Kio par défaut. Les répétitions identiques dans une version sont
  regroupées avec leurs références alternatives dans ces bornes. Les
  fragments d'origines distinctes restent citables séparément.

### Commandes

```bash
python -m argos knowledge init
python -m argos knowledge search '"strict transport" certificat' --limit 10
python -m argos knowledge exact 'RFC 9110' --source mdn
python -m argos knowledge exact 'doc:mdn/etag'
python -m argos knowledge index-status
python -m argos knowledge index-verify
python -m argos knowledge index-rebuild
```

Ajouter `--collection mission --scope-id UUID` avant la sous-commande
pour une mission. `search` et `exact` acceptent `--source`, `--domain`,
`--tag`, `--declared-version`, `--limit` et `--max-bytes`. `search`
accepte aussi `--title-weight` et `--body-weight`.

### Qualification locale

Le [probe de production](../../benchmarks/retrieval/production_probe.py)
sépare les jugements historiques documentaires des fixtures annotées au
niveau passage. Le scénario de charge génère un corpus distinct de
100 000 fragments, sans télécharger de données. Chaque scénario utilise
une base temporaire propre.

```bash
python -m benchmarks.retrieval.production_probe mdn
python -m benchmarks.retrieval.production_probe fixture
python -m benchmarks.retrieval.production_probe load
```

#### Qualité documentaire et qualité passage

| Jeu | Requêtes | Recall@5 | Recall@10 | MRR | nDCG@10 | Exactitude au rang 1 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| MDN M3.5-E, documents, BM25 | 134 | 77,2 % | 81,6 % | 0,643 | 0,672 | 26/27 identifiants historiques, avec BM25 |
| Fixtures, passages, BM25 | 6 | 100 % | 100 % | 1,000 | 1,000 | — |
| Fixtures, passages, SQL exact | 12 | 100 % | 100 % | 1,000 | 1,000 | 8/8 références présentes, 4/4 absentes sans résultat |

La campagne MDN utilise les 38 fichiers épinglés et 299 fragments fixes.
Le probe prend jusqu'à 50 passages avant regroupement par document. Les 12
requêtes historiques sans réponse ont toutes reçu des résultats lexicaux.
Les fixtures vérifient des repères contrôlés, des accents et expressions,
des références positives et des versions ou identifiants absents. Leur
faible taille limite la généralisation. Le jeu historique ne constitue pas
une qualification indépendante au niveau passage.

#### Temps et ressources

Mesures Linux avec SQLite 3.53.1. Les temps de recherche incluent
l'ouverture SQLite, le classement et la construction des résultats. Le
cache du système n'a pas été purgé. Le RSS est le pic du processus de
qualification. La taille SQLite inclut les originaux et les projections.

| Scénario | Mesure | Python 3.12.15 | Python 3.14.6 |
| --- | --- | ---: | ---: |
| MDN | BM25 p50 / p95 | 31,9 / 53,2 ms | 47,1 / 62,1 ms |
| MDN | Indexation / reconstruction / vérification | 139 / 68 / 73 ms | 155 / 63 / 75 ms |
| MDN | Modification de 3 fragments, préparation / publication / rejeu | 5,8 / 3,6 / 3,1 ms | 4,9 / 3,1 / 2,6 ms |
| MDN | RSS / SQLite | 28,8 / 1,71 Mio | 29,4 / 1,71 Mio |
| 100 000 fragments synthétiques | BM25 sélectif p50 / p95 | 5,6 / 6,6 ms | 3,1 / 3,7 ms |
| 100 000 fragments synthétiques | BM25 terme présent partout p50 / p95 | 522 / 574 ms | 519 / 600 ms |
| 100 000 fragments synthétiques | SQL exact p50 / p95 | 5,4 / 6,7 ms | 3,4 / 5,6 ms |
| 100 000 fragments synthétiques | Indexation / reconstruction / vérification | 7,93 / 8,91 / 7,15 s | 8,62 / 8,97 / 6,85 s |
| 100 000 fragments synthétiques | Modification d'un document à 1 000 fragments, préparation / publication / rejeu | 26 / 149 / 6 ms | 14 / 84 / 5 ms |
| 100 000 fragments synthétiques | RSS / SQLite après reconstruction | 41,2 / 83,9 Mio | 43,6 / 83,9 Mio |

Le terme commun couvre tout le corpus synthétique, même avec une limite
de dix résultats. La mise à jour incrémentale reste à la granularité du
document publié. Les relevés bruts sont sous
`data/qualification/m353-retrieval/`. Aucun modèle, corpus ou index ne
figure dans le patch Git.

Les 88 tests documentaires passent sous les deux interpréteurs. Ils
couvrent la migration v2, les publications concurrentes, la reprise après
arrêt du processus, les retraits, la révocation d'une collection et la
détection puis la reconstruction d'un index altéré. La suite régulière
compte 1 364 réussites et 122 ignorés sous chaque interpréteur. Ruff, le
formatage, Pyright et `git diff --check` passent également.

## M3.5.4 — Embeddings et récupération vectorielle

### Fournisseur et espaces compatibles

`EmbeddingProvider` définit l'identité de l'espace, le prétraitement
document/requête et l'embedding par lots. `OllamaEmbeddingProvider`
appelle uniquement le runtime local sur `127.0.0.1`. Il vérifie la
version du runtime et le digest annoncé par `/api/tags` avant et après
chaque lot. Un tag absent est indisponible, un digest ou runtime différent
est une erreur d'intégrité. Les délais, tailles de réponse et d'entrée
sont bornés, sans redirection ni proxy. Le lot par défaut est de 16,
avec un maximum de 32 et 256 Kio par lot. La troncature implicite côté
serveur est désactivée.

| Profil | Dimensions | Prétraitement |
| --- | --- | --- |
| `embeddinggemma:300m` | 768 par défaut, 256 et 512 autorisées | `embeddinggemma-search-v1`, préfixe distinct pour documents et requêtes. Candidat sous réserve des conditions Gemma. |
| `qwen3-embedding:0.6b` | 512 par défaut, 256 et 1024 autorisées | `qwen3-technical-search-v1`, instruction côté requête, titre et texte côté document. |

Les vecteurs natifs sont projetés par préfixe de dimensions puis
normalisés en Float32, selon les conventions de M3.5-E. Le pin Qwen
est le digest annoncé par Ollama et diffère du SHA du fichier manifeste
conservé localement. Les profils sont sélectionnés explicitement.
Les licences et empreintes de référence sont documentées dans le
[rapport M3.5-E](M35_RETRIEVAL_BENCHMARK.md#consolidation-du-26-novembre-2026).

### SQLite v4 et cycle de vie

`argos knowledge init` migre le fichier de la collection. La migration
ne construit aucun embedding. Chaque espace est identifié par le
fournisseur, le runtime, le digest modèle, le prétraitement et les
dimensions, avec versionnement du stockage cosinus Float32.

| Ajout SQLite v4 | Rôle |
| --- | --- |
| `vector_space` | Identité de configuration et dimension attendue. |
| `vector_cache` | Un vecteur Float32 little-endian unitaire et son SHA-256 pour chaque empreinte d'entrée prétraitée, dans cet espace et cette collection. |
| `vector_link` | Association des fragments publiés aux vecteurs, supprimée dans la transaction qui retire ou remplace leurs fragments. |

Le calcul se fait hors transaction. Avant d'enregistrer un lot, la
construction revérifie le fragment courant et le digest de son entrée.
Les lots validés servent à la reprise après interruption. Les archives
de contenu et le cache restent privés dans la collection. Les entrées
orphelines peuvent être réutilisées au rejeu ou écartées par une
reconstruction explicite avec `--discard-cache` pour l'espace demandé.

Un changement d'identité ouvre un nouvel espace à construire. Un
espace est prêt quand tous les fragments SQL courants ont leur lien.
Une mise à jour suspend donc la recherche dense dans cet espace jusqu'au
rattrapage, avec repli lexical disponible. La reconstruction remplace
les liens et réutilise les vecteurs intègres sans appel Ollama pour
les entrées déjà en cache. Une reconstruction SQL peut également
supprimer les liens et demander un rejeu vectoriel depuis ce cache.

### NumPy, routage et abstention

`NumPyKnowledgeRetriever` implémente le contrat `KnowledgeRetriever`.
Il vérifie l'autorisation et filtre les fragments avant lecture des
vecteurs. Le classement cosinus exact traite des blocs de 128 lignes,
vérifie SHA-256, dimension, valeurs finies et norme puis conserve un
nombre borné de candidats. La provenance, les citations et les budgets
de restitution suivent M3.5.3, avec départage par source, document et
ordinal. Le modèle n'est sollicité ni pour une collection vide ni pour
un filtre qui exclut tous les fragments. Les vecteurs de requêtes restent
en mémoire pendant la recherche.

`RetrievalRouter` expose les modes `exact`, `lexical`, `dense` et
`auto`. Le mode automatique privilégie les identifiants documentaires
et techniques explicites. Une référence explicite absente rend
`no_match`. Pour les autres demandes, le routeur essaie le dense et
retombe sur BM25 si le fournisseur est indisponible ou l'espace
incomplet. L'enveloppe indique `provider_unavailable` ou
`index_not_ready` comme motif de repli. Une erreur d'intégrité ou une
réponse invalide du fournisseur remonte à l'appelant. RRF et reranking
restent reportés.

`CosineCalibration` associe un minimum cosinus à l'identité de l'espace
et à un corpus nommé. Une recherche dense sous le seuil rend `no_match`
sans repli automatique. Le score est une similarité de récupération.
La véracité et l'appui d'une affirmation demandent une validation
distincte. Les deux seuils ci-dessous sont des résultats de calibration
sur MDN, sans valeur par défaut pour une autre collection.

### Commandes et ressources

```bash
python -m argos knowledge init
python -m argos knowledge vector-build --model qwen3-embedding:0.6b
python -m argos knowledge retrieve 'revalidation HTTP par ETag' --mode dense \
  --model qwen3-embedding:0.6b
python -m argos knowledge retrieve 'Que décrit RFC 9110 ?' --mode auto
python -m argos knowledge vector-status --model qwen3-embedding:0.6b
python -m argos knowledge vector-cache --model qwen3-embedding:0.6b
python -m argos knowledge vector-verify --model qwen3-embedding:0.6b
python -m argos knowledge vector-rebuild --model qwen3-embedding:0.6b
python -m argos knowledge vector-unload --model qwen3-embedding:0.6b
```

Le port par défaut est 11536 pour le runtime parallèle déjà installé.
Le choix du modèle, de la dimension, du digest et du runtime doit être
cohérent pour toute la série de commandes. Pour activer l'abstention,
fournir ensemble `--minimum-cosine` et `--calibration-corpus` à
`retrieve`. Les filtres et la sélection de collection de M3.5.3 restent
disponibles.

NumPy 2.5.5 est la seule dépendance ajoutée. Le runtime qualifié utilise
un seul modèle simultané avec `OLLAMA_NUM_PARALLEL=1`. La durée de
résidence est configurable et le déchargement explicite cible uniquement
le digest sélectionné. La future orchestration devra réserver la VRAM
entre embeddings et génération. Le pilote a mesuré le déchargement
séquentiel des embeddings, sans appel génératif.

### Qualification locale

Le [probe vectoriel](../../benchmarks/retrieval/vector_probe.py) utilise
les 38 documents épinglés de M3.5-E, 299 fragments et les jugements
documentaires historiques. Le seuil est choisi sur les 20 requêtes de
développement puis appliqué aux 134 requêtes historiques. Un second
scénario construit 100 000 vecteurs synthétiques distincts dans une base
temporaire, sans Ollama.

```bash
python -m benchmarks.retrieval.vector_probe mdn --model qwen3-embedding:0.6b \
  --work-root data/qualification/m354-vector
python -m benchmarks.retrieval.vector_probe mdn --model embeddinggemma:300m \
  --work-root data/qualification/m354-vector
python -m benchmarks.retrieval.vector_probe synthetic \
  --work-root data/qualification/m354-vector
```

| Modèle | Recall@5 / Recall@10 | MRR / nDCG@10 | Seuil MDN | Abstentions correctes | Résultats pertinents perdus |
| --- | ---: | ---: | ---: | ---: | ---: |
| EmbeddingGemma 768 | 97,5 % / 99,2 % | 0,840 / 0,872 | 0,418580 | 10/12 | 9 |
| Qwen3 512 | 99,6 % / 100 % | 0,863 / 0,889 | 0,458773 | 5/12 | 0 |

Le classement ci-dessus est calculé avant seuil. Les pertes comptent
les requêtes dont une réponse pertinente apparaissait parmi les dix
premiers documents puis a été écartée par le seuil. Sur les 27 requêtes
d'identifiants historiques, le dense a placé le bon document au premier
rang 27 fois avec Gemma et 26 fois avec Qwen. Le routeur a résolu les
quatre références documentaires explicites utilisées sur MDN et
correctement renvoyé une absence. Il a aussi réussi les dix replis
lexicaux par modèle avec un port Ollama local indisponible.

| Mesure locale Python 3.14.6 | EmbeddingGemma 768 | Qwen3 512 |
| --- | ---: | ---: |
| Latence chaude p50 / p95 | 121,6 / 144,5 ms | 105,0 / 132,0 ms |
| Requête après déchargement du modèle | 5,42 s | 4,23 s |
| Construction initiale / reconstruction depuis cache | 16,81 / 0,38 s | 26,85 / 0,36 s |
| Réindexation d'une version à trois fragments | 137 ms, 1 calcul et 2 réutilisations | 127 ms, 1 calcul et 2 réutilisations |
| SQLite total / blobs du cache initial | 3,08 Mio / 897 Kio | 3,09 Mio / 598 Kio |
| RSS crête client / serveur Ollama et descendants | 55,2 / 1 226 Mio | 55,0 / 881 Mio |
| VRAM crête mesurée par échantillonnage | 787 Mio | 1 289 Mio |
| Déchargement / VRAM ensuite | 373 ms / 0 Mio | 234 ms / 0 Mio |

Les deux reconstructions ont réutilisé les 299 vecteurs sans appel de
calcul. La mesure à froid décharge le modèle et garde le cache disque de
l'OS. Les latences chaudes incluent les vérifications Ollama, SQLite,
le classement et la restitution de jusqu'à 50 passages. Elles diffèrent
du microbanc M3.5-E, qui mesurait notamment une matrice NumPy déjà chargée.

Sur les **100 000 vecteurs synthétiques 512D**, les dix requêtes ont
retrouvé leur passage cible au premier rang. L'indexation prend **103,2 s**,
la reconstruction **87,0 s** avec 100 000 réutilisations et la
vérification **15,0 s**. Le parcours complet lit et contrôle les vecteurs
depuis SQLite. Sa latence p50/p95 est de **6,55 / 7,54 s** et son RSS
crête de **57,7 Mio**. La base complète occupe **525,7 Mio**, dont
**195,3 Mio** de vecteurs bruts. Le remplacement d'une version à 1 000
fragments prend **229 ms** à publier puis **1,38 s** à réindexer, avec
un nouveau vecteur et 999 réutilisations. Cette latence de recherche
limite l'usage interactif à cette échelle avec le parcours actuel.

Les **108 tests documentaires** réussissent sur Python 3.12.15 et 3.14.6.
La suite complète réussit avec **1 385 tests passés et 121 ignorés**
sur chacun. NumPy active un test auparavant ignoré. Ruff, le formatage,
Pyright, `git diff --check` et la validation du verrou hors ligne passent.

Les relevés privés sont sous `data/qualification/m354-vector/`. Les huit
manifestes Ollama sont identiques avant et après l'essai et les 34 blobs
référencés sont présents aux tailles attendues. Les deux runtimes et ces
données restent en place. Le compromis Gemma/Qwen et la calibration
doivent être rejugés sur un corpus indépendant au niveau passage.

## M3.5.4.1 — Performance de la recherche vectorielle

### Périmètre des mesures

Le p95 de 19,35 ms dans [M3.5-E](M35_RETRIEVAL_BENCHMARK.md#résultats-lexicaux-et-charge)
couvre le produit matriciel et la sélection des dix voisins de 100 000
vecteurs 512D déjà normalisés et en mémoire. Les 7,54 s de M3.5.4 couvrent
le parcours de production avec un fournisseur synthétique. Chaque requête
ouvre SQLite, contrôle la portée et la disponibilité, lit et vérifie les
vecteurs, calcule les scores, classe les candidats et résout les citations.
La génération de l'embedding par Ollama est un autre périmètre.

### Vue NumPy retenue

`knowledge init` migre SQLite de v4 à v5. `vector_generation` conserve
une révision transactionnelle et une marque de validation. Ces valeurs
changent avec les associations ou les données susceptibles d'invalider la
vue. `vector_member_identity` distingue les incarnations d'un même ID
de fragment SQLite. Une reconstruction SQL ou la réutilisation d'un
identifiant ne permet donc pas de reprendre le vecteur d'un ancien fragment.

Le moteur conserve une matrice Float32 contiguë et immuable par instance
de récupérateur, pour la collection et l'espace déjà autorisés. Il ouvre
une nouvelle transaction de lecture à chaque requête et vérifie l'état
du stockage, les permissions Unix, la portée, la disponibilité et la
révision. Le préfiltrage SQL est appliqué avant le produit scalaire quand
des filtres sont demandés. La partition sélectionne le top-k en départageant
les ex æquo dans le même ordre que le moteur par blocs. Les passages du
top-k sont résolus et vérifiés dans la transaction courante.

Au changement de génération, les lignes dont l'identité et l'entrée sont
inchangées sont recopiées depuis la vue vérifiée. Seules les autres sont
relues et revalidées. Si le contenu du cache persistant ou une donnée
d'intégrité est modifiée, la marque de validation empêche cette reprise.
Une publication qui laisse la couverture incomplète rend l'espace
indisponible jusqu'au rattrapage. Un retrait validé est visible dès la
requête suivante et une ancienne citation est rejetée à sa résolution.

Le budget par instance est de 320 Mio pour la matrice et ses tableaux
d'identité. Un rafraîchissement peut garder temporairement l'ancienne
et la nouvelle vue. Au-delà du budget, le moteur utilise son parcours
par blocs. Les lectures indépendantes partagent la vue et construisent
la nouvelle génération sous verrou. Le cache bénéficie au consommateur
qui conserve son récupérateur. Chaque invocation du CLI repart à froid
côté matrice.

### Qualification

Le [probe](../../benchmarks/retrieval/vector_performance.py) construit six
bases synthétiques indépendantes, avec 1 000, 10 000 et 100 000 vecteurs
en 512D et 768D. Les recherches utilisent une requête et dix passages
dans les variantes mesurées. Les mesures à froid correspondent à une
vue NumPy absente, sans purge du cache disque de l'OS. Le banc compare
à chaque taille le résultat complet du moteur par blocs et celui du cache,
teste quatre lecteurs simultanés, puis republie et retire une version.

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  python -m benchmarks.retrieval.vector_performance --count 100000 \
  --dimension 768 --work-root data/qualification/m3541-vector
```

Les valeurs suivantes sont en millisecondes. Le banc utilise 20 répétitions
à chaud, trois démarrages à froid et quatre répétitions du chemin par blocs.
Le parcours synthétique complet inclut un calcul de requête synthétique.

| Vecteurs | Dimensions | Par blocs p50 / p95 | À froid p50 / p95 | À chaud p50 / p95 | Complet synthétique p95 | Vue RAM / SQLite (Mio) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 000 | 512 | 67,0 / 69,5 | 75,8 / 83,3 | 7,2 / 8,6 | 9,5 | 2,0 / 5,7 |
| 1 000 | 768 | 57,3 / 61,1 | 73,2 / 73,9 | 7,2 / 9,8 | 11,7 | 3,0 / 5,7 |
| 10 000 | 512 | 671,1 / 694,4 | 718,4 / 721,5 | 19,7 / 22,6 | 27,3 | 20,1 / 53,3 |
| 10 000 | 768 | 673,7 / 709,4 | 681,9 / 695,9 | 16,7 / 17,8 | 27,5 | 29,9 / 53,3 |
| 100 000 | 512 | 7 827,3 / 8 435,1 | 9 908,1 / 10 968,2 | 72,8 / 76,3 | 108,1 | 201,4 / 529,1 |
| 100 000 | 768 | 9 467,1 / 9 912,6 | 10 581,1 / 11 000,5 | 101,2 / 109,8 | 147,9 | 299,1 / 529,1 |

À 100 000 lignes, le chargement vérifié de la vue via une première
requête mesure 9,55 s en 512D et 10,87 s en 768D.
Le RSS crête de tout le banc atteint 882,0 et 1 273,5 Mio,
en incluant le mapping expérimental et des vues concurrentes. Après
avoir republié un document de 1 000 fragments, le calcul des embeddings
de reprise prend 1,74 / 1,81 s avec un seul nouveau vecteur et 999
réutilisations par dimension. La remise à jour de la vue prend
1,38 / 2,32 s contre 9,86 / 11,53 s pour un rechargement intégral.
La vue complète est recopiée pendant ce rafraîchissement incrémental.
Après retrait, la première recherche prend 1,29 / 1,67 s pour les
deux dimensions et ne renvoie aucun passage de la version retirée.

Le p95 avec un filtre couvrant toute la collection est de 624 / 643 ms
en 512D/768D. Le travail SQL de sélection reste conséquent. Les groupes
de quatre lectures simultanées terminent en 222 / 242 ms au p95
du groupe. Toutes les réponses concordent avec les lectures séquentielles.
Le p95 passe sous 150 ms à chaud après sélection de la collection
autorisée. Le filtre large et le redémarrage à froid dépassent cet objectif.

Le profilage isolé à 100 000 × 512D répartit les coûts suivants.
Les essais de préfiltrage, classement et citation sont chronométrés
séparément du scan et leurs valeurs ne s'additionnent donc pas.

| Phase | Temps mesuré |
| --- | ---: |
| Contrôle des permissions | 0,30 ms |
| Ouverture SQLite | 0,21 ms |
| Identité du schéma et disponibilité | 20,26 ms |
| Parcours SQL des membres autorisés | 374,92 ms |
| Lecture SQLite des vecteurs et conversion en valeurs Python | 7 169,96 ms |
| Contrôle des entrées et SHA-256 | 734,36 ms |
| Assemblage Float32 | 51,01 ms |
| Contrôle des normes | 201,01 ms |
| Similarités par blocs | 32,04 ms |
| Similarités sur matrice contiguë à chaud, p95 | 17,89 ms |
| Top-10 par partition / tri complet, p95 | 0,81 / 16,14 ms |
| Résolution et contrôle de dix citations, p95 | 8,69 ms |

Le mapping expérimental ne réduit pas le p95 à chaud du produit
scalaire dans ce cas (18,9 ms contre 17,9 ms) et demande un fichier additionnel.
La connexion réutilisée économise l'ouverture et les vérifications
du microtest (p95 1,41 ms contre 0,004 ms pour la lecture seule du
marqueur). Ce gain ne motive pas de conserver une connexion partagée.

Avec Qwen3 installé sur Ollama 0.40.18 et 299 fragments MDN, une même
question HTTP répétée 20 fois donne un p50/p95 complet de
43,6 / 48,8 ms, contre 11,8 / 14,0 ms avec le vecteur
de requête déjà calculé. La première requête après déchargement mesure 4,51 s.
Cette mesure de latence réelle ne constitue pas une qualification de pertinence.
Les relevés privés sont sous `data/qualification/m3541-vector/`.

Les 112 tests documentaires passent sous Python 3.12.15 et 3.14.6.
Chaque suite complète compte 1 389 réussites et 121 ignorés. Ruff,
formatage, Pyright et `git diff --check` passent. Les huit manifestes
Ollama restent inchangés et le serveur de mesure a été arrêté.

Qwen3 512 devient le candidat principal provisoire. EmbeddingGemma 768
reste disponible sous les conditions applicables. Les profils, digests
et seuils restent ceux de M3.5.4. Aucun recalibrage sur le jeu final
historique.

## F / M3.5.5 — Contexte et analyste consultatifs V2

Le contrat `consultative-context-v2` assemble une revue d’archive ou une
question documentaire explicite. `ReviewContextV2` raccorde les
[snapshots M3.1](M31_FOUNDATIONS.md), les preuves vérifiées par les lecteurs
d’archive, la [mémoire M3.4](M34_MEMORY_ENGINE.md) et jusqu’à quatre collections
explicitement autorisées. Les contrats des [analyses V1](M32_LOCAL_LLM_ANALYST.md)
et du [journal de revue](M33_SUPERVISED_REVIEW.md) restent disponibles. La
décision de conception est décrite dans l’[ADR du contexte V2](../architecture/adr/0007-consultative-context.md).

- Pour une question documentaire, le routeur prend la question explicite. Pour
  une archive, la requête utilise des statuts HTTP et les noms de technologies
  du catalogue expurgé. L’objectif de l’opérateur est transmis séparément.
  Le routeur réutilise le SQL exact, le dense et le repli lexical existants.
  Qwen3-Embedding 512 est le candidat CLI par défaut. EmbeddingGemma 768
  reste disponible aux conditions du modèle. Un seuil dense exige une
  identité de corpus explicite. Les seuils historiques restent inchangés.
- Le journal mémoire est contrôlé dans le périmètre UID, mission et snapshot.
  Seuls les éléments `verified_archive` admissibles rejoignent le contexte.
  L’assembleur déduplique l’observation par identité entre archive et mémoire,
  conserve les origines distinctes et expose les omissions.
- Le trio taille de fenêtre, octets UTF-8 de la consigne encadrée et nombre
  d’unités est contrôlé avant envoi. La priorité va aux contradictions et
  incertitudes, puis aux observations et passages, puis aux inférences.
  Les places disponibles dans une même priorité sont partagées entre
  composants. Les passages utilisent un préfixe déterministe de 1 200
  caractères par défaut. Les repères du fragment original sont conservés.
  La fenêtre initiale est de 8 192 tokens, dont 384 réservés à la sélection,
  et le plafond indépendant est de 32 768 octets et 48 unités.
- Le fournisseur `Selector` est interchangeable. L’adaptateur livré épingle
  Qwen3 4B par digest local et version d’Ollama, vérifie la fenêtre GGUF et utilise
  un prompt Qwen3 encadré. Le JSON échappe les marqueurs de contrôle de rôle.
  La borne avant envoi est calculée en octets encadrés avec marge pour les
  jetons spéciaux du tokenizer Qwen3. Les compteurs d’entrée et de sortie
  exposés après inférence proviennent d’Ollama. Une réponse dépassant une
  limite ou privée de compteurs valides est refusée.
- Le contrat `consultative-analyst-v2` restitue des extraits et observations
  sélectionnés par identifiants locaux à la tentative. Argos construit la
  synthèse par gabarit et les relations typées `observed_in_archive`,
  `inferred_in_archive` et `excerpt_from_document`. Les contradictions,
  incertitudes et limites transmises sont restituées indépendamment du choix
  du modèle. La section M3.5.6.1 décrit les niveaux d’appui utilisés pour
  décider de l’abstention à partir des éléments sélectionnés.
- Les versions supplantées ou retirées sont exclues par le Knowledge Engine.
  Les passages approuvés étiquetés `lifecycle=obsolete` sont omis et comptés.
  Les passages étiquetés `lifecycle=contradictory` sont restitués comme
  contestés par leur source ou leur opérateur. Le pilote ne déduit pas de
  contradiction sémantique entre passages et ne la tranche pas. Une citation
  admissible démontre le lien avec l’extrait transmis, sans établir la vérité
  de l’extrait ou sa pertinence pour toutes les questions.
- Le validateur relit l’archive, la tête de mémoire et les révisions documentaires
  avant et après l’inférence. Il résout les références sous les droits courants
  et compare la provenance et le condensat du préfixe transmis. Le retrait,
  le changement d’autorisation et la modification d’une génération bloquent la
  restitution. La vérification se fait par lecture de chaque magasin. Il n’y a
  pas de transaction couvrant tous les magasins et l’affichage au terminal.
- La revue V2 épingle avant la sélection les références, révisions, digests,
  budget et empreinte du contexte transmis dans la chaîne existante.
  Le journal conserve les identifiants sélectionnés, compteurs et états, ainsi
  qu’une empreinte de réponse. Le prompt, les extraits et la sortie brute de
  l’analyste V2 sont transitoires. L’acceptation exige le même périmètre et
  revalide les données au moment de la décision. L’interruption rejette une
  sortie tardive par vérification de la tête du journal.

### Commandes

Après initialisation des collections par `knowledge init` et publication
des documents, le mode auto utilise le fournisseur d’embeddings et l’index
vectoriel existants. Le mode lexical fonctionne sans ce fournisseur.

```bash
python -m argos review context-v2 --collection user --mode exact \
  --objective 'doc:mdn/etag'
python -m argos review documentary-v2 --collection user --mode lexical \
  --objective 'Quel est le rôle d’un ETag ?'
python -m argos review workflow-analyze-v2 --db "$ARCHIVE" --journal "$JOURNAL" \
  --review-id "$REVIEW_ID" --collection user --memory --objective 'Relire les observations'
python -m argos review workflow-accept --db "$ARCHIVE" --journal "$JOURNAL" \
  --review-id "$REVIEW_ID" --collection user --memory --input "$DECISION"
```

L’archive et le journal utilisent les permissions du parcours V1. `--memory`
choisit `ARGOS_MEMORY_HOME` ou la zone `memory` de `ARGOS_DATA_HOME`.
`--memory-root` sélectionne un emplacement explicite. Le moteur de connaissances
continue à résoudre ses magasins sous `ARGOS_DATA_HOME`. Le mode documentaire
utilise la collection privée utilisateur par défaut. Une revue d’archive doit
indiquer les collections voulues. Une collection mission est liée à la mission
du journal. Les collections organisationnelles restent indisponibles.

### Qualification locale

Trois documents MDN présents localement ont donné 11 fragments. Une même
question ETag a été répétée trois fois par scénario sur les deux installations
Ollama 0.11.11 et 0.40.18, avec Qwen3 4B et Qwen3-Embedding 512. Le contexte,
les citations et les compteurs étaient identiques sur les neuf appels.
Le modèle a retenu six extraits dont cinq de la page ETag. Le contexte encadré
de 6 914 octets avait une borne de 6 922 tokens. Ollama a compté 1 971 tokens
d’entrée et 25 de sortie par appel. Une inspection CLI a trouvé la référence
exacte et une autre a confirmé le repli FTS5 avec le serveur d’embeddings arrêté.

| Résidence | Premier appel complet | Deux appels suivants | Pic VRAM GPU échantillonné | Pic RAM PSS des deux groupes Ollama |
| --- | ---: | ---: | ---: | ---: |
| Séquentielle avec expiration à chaque appel | 21,05 s | 14,17 / 13,01 s | 4 337 Mio | 3 044 Mio |
| Embeddings CPU résidents et génération GPU | 11,13 s | 1,27 / 1,24 s | 4 271 Mio | 3 994 Mio |
| Les deux résidents sur GPU | 9,15 s | 1,02 / 1,04 s | 5 556 Mio | 3 498 Mio |

Sur les neuf appels, l’assemblage a pris 0,3 à 0,7 ms et les deux passes de
validation 26 à 37 ms. Pour les deux appels suivants de chaque scénario,
récupération puis génération ont pris respectivement 4,29–6,41 s et
6,21–9,48 s en séquentiel, 184–211 ms et 846–851 ms en CPU/GPU, et
37–49 ms et 825–836 ms en résidence GPU simultanée. Le runtime génératif
a signalé 2,05 à 9,66 s pour démarrer le runner à froid selon le scénario.
La première requête d’embeddings a pris 3,27 s sur CPU et 3,66 s sur GPU
dans les scénarios résidents, chargement et calcul inclus. Le point de passage
séquentiel a observé l’absence du modèle d’embeddings après 208 à 231 ms
d’attente suivant sa requête. La fenêtre reste fixée à 8 192 tokens pendant
l’essai.

Rejouer depuis la racine sur Linux avec les deux runtimes locaux et un dossier
de sortie neuf. Les mesures brutes, logs et la base d’essai sont privés sous
`data/qualification/m355-context/`.

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m \
  benchmarks.retrieval.consultation_probe --out data/qualification/m355-replay
```

Le protocole versionné a répété les neuf sélections avec les mêmes
références de fragments, extraits et compteurs. Sur ce second essai, les deux
appels résidents ont pris 1,27–1,78 s en CPU/GPU et environ 1,24 s en GPU/GPU.
Le pic GPU/GPU était à nouveau de 5 556 Mio. Les mesures de ce rejeu sont
conservées dans `data/qualification/m355-replay/`. Les huit manifestes
installés conservent leurs empreintes et le GPU était revenu à 0 Mio à
la fin des essais.

Ces essais qualifient le raccord local et l’occupation échantillonnée
sur une RTX 4060 Laptop de 8 Gio. Les deux variantes résidentes gardent les
modèles chargés pour les deux appels suivants, tandis que le séquentiel
déclenche de nouveaux chargements. Les pics PSS concernent les processus
Ollama et excluent le processus Argos. En production le CLI demande une
expiration immédiate pour les modèles utilisés. Il ne coordonne pas les
demandes d’autres processus ni ne garantit la disponibilité de la VRAM.
La résidence simultanée reste un réglage expérimental. L’essai réel
a utilisé Qwen3-Embedding. L’alternative Gemma et les parcours archive et
mémoire ont été couverts par les contrats et tests locaux, avec le raccord
archive et mémoire testé par fournisseur simulé.

La matrice NumPy reste froide au premier chargement d’un processus CLI.
À 100 000 vecteurs, les rafraîchissements restent de l’ordre de la seconde
ou davantage, les filtres couvrant tout le corpus et les lectures multiples
peuvent dépasser 150 ms, et un rafraîchissement peut temporairement conserver
deux vues. Voir les mesures précises de M3.5.4.1 ci-dessus. La pertinence
inter-domaines, l’abstention calibrée de bout en bout et la robustesse
sémantique à l’injection relèvent de la qualification indépendante M3.5.6.

## G / M3.5.6 — Qualification de bout en bout

Le [bilan M3.5.6](M356_RAG_EVALUATION.md) documente les cinq bras appariés,
les seuils figés, les trois replays d’archive, les mesures de ressources
et les commandes. Le corpus de 115 cas est distinct de M3.5-E. Ses annotations
proviennent d’un seul assistant.

Le RAG améliore l’exactitude du verdict structuré de 47,8 % à 81,7 % face
au LLM seul sur ce jeu. Les seuils absolus du pilote génératif échouent sur
l’exactitude, la précision des citations, l’appui et l’abstention. Le
Memory Engine n’a apporté aucun nouvel élément après déduplication sur les
trois replays crAPI, DVWA et Juice Shop. Les deux embeddings satisfont le
seuil de rappel. Gemma obtient le meilleur classement de passages sur
ce corpus, tandis que le gain de verdict est mesuré avec Qwen3-Embedding.

Le contrat extractif V2 garde son rôle de restitution consultative. Les
priorités de qualification portent sur l’abstention avec des distracteurs,
les contradictions, la validation indépendante des appuis et la séparation
entre verdict généré et sélection extractive.

### M3.5.6.1 — Appui des affirmations et abstention

La politique `extractive-grounding-v1` conserve le contrat V2 et qualifie
chaque élément et le degré d’appui de l’objectif. Les observations vérifiées
sont bornées au constat archivé. Un passage approuvé et résolu appuie
l’attribution de son texte exact à sa source. Les inférences, hypothèses,
conflits déclarés et inconnues conservent leur statut. Les contrôles de
droits, de provenance, de version et de fraîcheur s’appliquent avant et
après sélection. Une demande `citation exacte: <texte>` peut vérifier
déterministement un passage complet dans le contexte sélectionné.

Les réponses ordinaires peuvent rendre des éléments partiels et signaler
explicitement que leur implication pour l’objectif reste indéterminée. Le
[bilan M3.5.6.1](M3561_RAG_RELIABILITY.md) mesure le coût de cette prudence.
Aucun des deux embeddings ne permet d’atteindre les portes du pilote sur
ce jeu. Les prochains essais doivent mesurer un appui par proposition, la
pertinence des extraits et la résolution des conflits propres à l’objectif.

## H — Maintenance conçue

L'actualisation compare contenu brut, normalisation et versions de parsers,
découpage et modèles. Recalculer les passages modifiés et publier une
génération cohérente par collection. Une vue NumPy dérivée peut être
reconstruite depuis les vecteurs stockés et versionnés. La rétention des
originaux rend possible une nouvelle normalisation. Le retrait devra
invalider passages, index et caches dans le même périmètre.

Distinguer publication par l'éditeur, import et échéance de revue. Présenter
les sources contradictoires avec leur contexte et leur date. Une version
plus récente peut être inapplicable à la version concernée. La purge
physique, la sauvegarde et la conservation des citations ont leur propre
politique.

L'import Obsidian restera volontaire et privé. Traiter les transclusions,
liens, plugins et pièces jointes comme des données inertes. Une future
synchronisation publique fonctionnera dans une étape d'acquisition et
d'approbation séparée. Une acquisition échouée ne remplace pas la version
publiée.

## Dépendances et choix à valider

La poursuite du pilote exige des jugements indépendants de support sur
des documents à plusieurs passages, puis une nouvelle mesure des verdicts. Les résultats M3.5-E ne
qualifient ni les ACL multi-utilisateur, ni les mises à jour concurrentes,
ni les pics de mémoire à la reconstruction. Les lots de 16 et le choix
d'embeddings restent des hypothèses de pilote. Le plan d'implémentation et
l'ordre des qualifications figurent dans la [roadmap](ROADMAP.md#m35--connaissances-et-rag).
