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
| M3.5-D | Version par contenu et provenance, approbation explicite, base SQLite par frontière d'accès. Normalisation et index FTS5 comme projections dérivées. Index vectoriel interchangeable. | Sources, originaux et versions implémentés en M3.5.1. Normalisation, fragments et index conçus. |
| M3.5-E | NumPy exact, EmbeddingGemma 768 sous conditions Gemma et Qwen3 512 en alternative. Dense prioritaire, FTS5 en secours et recherche exacte SQL à qualifier. Lots de 16 à revalider, cache versionné, indexation incrémentale et préfiltrage obligatoire. RRF et reranker reportés. | Mesures de banc consolidées, choix du pilote provisoires. Voir le [rapport M3.5-E](M35_RETRIEVAL_BENCHMARK.md). |
| M3.5-F à H | Contexte consultatif versionné et borné, benchmark comparatif indépendant, maintenance avec retrait et reconstruction. | Conception ci-dessous. Les contrats de lecture sont le seul point d'entrée de cette tranche pour les futurs consommateurs. |

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
    Collection, CollectionKind, DocumentMetadata, DocumentRef, KnowledgeStore, Source,
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

## F — Contexte consultatif et analyse versionnée

Conserver les contrats de [snapshot et de projection M3.1](M31_FOUNDATIONS.md),
d'[analyse extractive M3.2](M32_LOCAL_LLM_ANALYST.md), de [revue M3.3](M33_SUPERVISED_REVIEW.md)
et de [mémoire M3.4](M34_MEMORY_ENGINE.md). Le snapshot vérifie la cohérence
de l'archive et expose sa couverture partielle. La mémoire admissible reste
bornée, expurgée et liée au même snapshot. Les droits d'exécution restent
la responsabilité du runtime, indépendamment des résultats consultatifs.

La v2 se sélectionne explicitement. Résoudre d'abord l'identité, la mission
et les collections autorisées. Épingler le snapshot, la tête mémoire et
les versions documentaires qui seront citées. Pour une question utilisateur,
récupérer dans les collections autorisées. Pour une analyse d'archive,
former la requête à partir de champs expurgés. Le préfiltrage s'applique
avant ouverture des index, score ou accès au cache.

Prioriser preuves, contradictions, incertitudes et couverture avant les
compléments. Regrouper par identité de preuve et de passage en conservant
les origines distinctes. Utiliser des extraits déterministes et compter les
omissions. Réserver un budget mesuré pour le gabarit, le schéma et la réponse.
La limite d'entrée dépend de la fenêtre effective du modèle. Un tokenizer
compatible ou une borne conservatrice qualifiée doit permettre le contrôle
avant envoi, avec des plafonds indépendants en octets, nombre d'entrées et
durée.

Le modèle reçoit des données expurgées et des références locales à la
tentative. Les instructions viennent d'Argos et les autorisations du
runtime. Le modèle sélectionne des unités citables et des relations typées.
La réponse du pilote reste extractive ou produite par gabarit. Chaque
citation doit viser le passage transmis, la bonne version et une source
admissible pour l'affirmation. Une référence documentaire explique une règle
générale et une preuve archivée établit une observation de mission. En cas
d'appui insuffisant, de contradiction non résolue ou de retrait, conserver
une réponse partielle ou une abstention motivée. La validation sémantique
de la prose libre reste une étape distincte.

La revue supervisée persiste la tentative avant l'inférence et vérifie de
nouveau preuves, droits et retraits avant restitution ou acceptation.
Préserver le rejet des réponses tardives et la reprise explicite. La
conservation des prompts complets v2 dépend d'une politique de rétention,
car ils peuvent contenir des extraits privés.

Sur l'hôte du pilote, comparer le séquencement embeddings puis génération
à une variante embeddings sur CPU. Deux serveurs Ollama ont des limites
indépendantes. Un futur garde de ressources coordonnera les chargements
Argos, vérifiera le déchargement et refusera un dépassement mesuré. Le
pilote ne décharge que ses propres modèles.

## G — Qualification de bout en bout

Comparer les cinq bras avec les mêmes questions, modèle, format de sortie
et plafonds. Exécuter LLM seul, LLM avec contexte de mission, puis contexte
avec mémoire, avec RAG et avec mémoire plus RAG. La version extractive v1
garde ses propres tests de non-régression. Une mémoire qui n'apporte aucun
nouvel élément après déduplication peut légitimement produire un gain nul.

Constituer un corpus indépendant avec plusieurs éditeurs, langues et
familles de documents. Préparer des cas synthétiques à vérité contrôlée,
des preuves partielles, des contradictions et des cas sans réponse ou hors
collection. Annoter les passages qui appuient ou réfutent chaque affirmation
et arbitrer un échantillon avec un second annotateur. Séparer les jeux par
famille de documents, mission et variante de question. Geler jugements,
seuils et configurations avant le test final. Le jeu final M3.5-E reste
un repère historique.

Mesurer pertinence, exactitude, couverture critique, appui des affirmations,
précision et rappel des citations, abstention correcte et réponses utiles
perdues, hallucinations brutes et rendues, tokens et ressources. Rapporter
latence par étape et à froid/chaud, RAM et VRAM, et écarts appariés par cas.
Les critères bloquants sont une fuite entre collections, une citation hors
droits rendue, une action déclenchée ou un dépassement de budget accepté.
Les seuils de qualité et de ressources seront fixés sur le jeu de réglage
avant l'ouverture du jeu final.

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

La prochaine tranche doit qualifier SQL exact, FTS5 et la résolution des
citations au niveau passage avant l'assemblage v2. Les résultats M3.5-E ne
qualifient ni les ACL multi-utilisateur, ni les mises à jour concurrentes,
ni les pics de mémoire à la reconstruction. Les lots de 16 et le choix
d'embeddings restent des hypothèses de pilote. Le plan d'implémentation et
l'ordre des qualifications figurent dans la [roadmap](ROADMAP.md#m35--connaissances-et-rag).
