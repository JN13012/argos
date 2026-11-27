# M3.5.7 — Maintenance documentaire et bilan M3.5

La maintenance est disponible localement sur les collections Argos. L’import
Obsidian a été qualifié sur des notes synthétiques. Le fournisseur public
livré lit un manifeste et des fichiers de test sur disque. Le pilote
génératif garde son statut non qualifié.

## Contrat de maintenance

`Maintenance.preview(manifest, review_days, remove_missing)` compare le
manifeste à la dernière publication gérée. Un changement d’octets ou de
métadonnées propose une nouvelle version. Les entrées identiques conservent
leur version, leur projection et leurs liens vectoriels. Un document absent
est signalé. L’option explicite `remove_missing` permet son retrait. Un
manifeste portant le tag `lifecycle=obsolete` déclenche le retrait logique
et conserve la version d’origine et la version marquée obsolète.

`Maintenance.apply(manifest, expected, fetch, ...)` exige l’empreinte du
plan qui lie la collection, la source, le manifeste, le point de départ et
les options de révision. La préparation lit uniquement les corps nouveaux
ou modifiés et vérifie leur longueur et leur SHA-256. L’écriture relit le
plan sous transaction SQLite. Un plan périmé exige une nouvelle inspection.
La transaction publie versions, projections et index SQL/FTS5 avec les
retraits et l’historique de maintenance. Un retrait coupe les liens
vectoriels courants et invalide la génération de la vue NumPy. Les octets
historiques restent retenus par la politique de stockage.

La révision se configure par source de 1 à 3 650 jours, avec 30 jours par
défaut. `Maintenance.report` expose le dernier contrôle, son échéance, le
statut de fraîcheur et les résultats des dernières maintenances. Un
manifeste incomplet donne le statut `incomplete` lorsque l’option de retrait
est désactivée. Une échéance de revue signale un contrôle à effectuer.
Elle ne modifie pas l’approbation des documents. Le plan est recalculé
sur demande et l’opérateur garde le déclenchement.

Le schéma SQLite v6 ajoute `maintenance_feed`, `maintenance_item` et
`maintenance_run`. Exécuter `knowledge init` sur chaque collection à
migrer. Les collisions avec un document géré manuellement sont rejetées.
Un retrait manuel reste opposable à la maintenance. Les identifiants
retirés par absence ou obsolescence restent tombstonés. Une réintroduction
demande une nouvelle identité documentaire, par exemple un nouveau chemin
relatif ou une nouvelle source approuvée.

### Cohérence dense

L’option d’embedding explicite rafraîchit uniquement les fragments modifiés
dans le même espace vectoriel et dans la transaction de publication. Un
échec conserve l’ensemble publié précédent, y compris ses vecteurs. Cette
option plafonne le lot à 1 024 fragments modifiés et tient le verrou d’écriture
pendant le calcul. Pour les lots longs, la publication documentaire peut
précéder `vector-build`. SQLite et FTS5 sont alors immédiatement cohérents.
La recherche dense attend de retrouver une couverture complète dans
l’espace demandé. Le repli lexical et les commandes de reconstruction
restent disponibles. Le cache de vecteurs validés reste réutilisable par
empreinte. Une révision invalide la vue NumPy correspondante.

## Import privé Obsidian

Le fournisseur `obsidian.scan` exige une racine locale, une source agréée
`obsidian:<identifiant>` et une ou plusieurs sélections relatives. Il
ouvre les composants de chemin sans suivre les liens symboliques. Les
liens multiples et les notes spéciales sont refusés. Les chemins cachés
et les correspondances aux exclusions sont ignorés. La racine, les
sélections et exclusions définissent le périmètre associé à une source.
Un changement de ce périmètre utilise une nouvelle source, ce qui protège
contre un retrait causé par une sélection différente.

Le frontmatter YAML borné fournit le titre et les tags. Le parseur lit
les données avec PyYAML 6.0.3, déjà présent dans le verrou avant son
usage direct. Alias, ancres, balises explicites, clés dupliquées et
structures trop profondes sont refusés. Les tags sont portés par la
dimension `obsidian`. Si un caractère ou une hiérarchie dépasse la
syntaxe des tags, l’identifiant canonique inclut une empreinte courte.
L’original, y compris ses autres champs YAML, reste accessible en tant
que contenu documentaire. La provenance conserve le chemin relatif
encodé. Les wikilinks, transclusions, plugins et consignes du texte restent
inertes. L’import se limite à la collection utilisateur privée.

Exemple avec une racine synthétique existante et une collection initialisée.

```bash
python -m argos knowledge init
python -m argos knowledge source-register notes --publisher Local \
  --origin obsidian:notes --rights Private
python -m argos knowledge source-approve notes
python -m argos knowledge obsidian-import notes --root ./fixture-vault \
  --select Guides --select Accueil.md --exclude 'Guides/Drafts/*' --dry-run
python -m argos knowledge obsidian-import notes --root ./fixture-vault \
  --select Guides --select Accueil.md --exclude 'Guides/Drafts/*' --apply "$PLAN_SHA256"
python -m argos knowledge maintenance-report notes
```

`PLAN_SHA256` prend la valeur de `plan.sha256` affichée au dry-run.
Les options de révision et de retrait restent identiques entre les deux
commandes. Ajouter `--remove-missing` au dry-run pour examiner les retraits
et à l’application pour les confirmer.

## Synchronisation publique simulée

`PublicProvider.manifest(source, release)` fournit une proposition
de version courante ou épinglée. `PublicProvider.fetch(source, release,
entry)` fournit un corps borné pour une entrée validée. L’application exige
la version et le SHA-256 du plan. Le registre contrôle l’approbation et la
concordance des droits déclarés. Les provenances HTTPS restent sous
l’origine et le chemin de la source déclarée. Une révision déjà publiée
avec un contenu différent ou une révision supplantée est refusée. Un échec
de lecture, de taille, de digest, de projection ou de publication laisse
le dernier état valide disponible. Tant que la base et la version proposée
restent identiques, le même plan est réapplicable après interruption.

Le CLI utilise `LocalManifestProvider`. Le JSON désigne des chemins
relatifs au répertoire qui héberge le manifeste. Voici un exemple pour
un fichier texte de 20 octets contenant `Example public text` et un saut
de ligne.

```json
{
  "source": "public-fixture",
  "release": "fixture-1",
  "rights": "Fixture rights",
  "entries": [{
    "id": "guide",
    "path": "guide.txt",
    "title": "Fixture guide",
    "origin": "https://docs.example.test/advice/guide",
    "media_type": "text/plain",
    "sha256": "3432c2f9b40e2c037896ec99e813a720d8786541c9596f6df2af86304742157c",
    "size": 20
  }]
}
```

```bash
python -m argos knowledge source-register public-fixture --publisher Fixture \
  --origin https://docs.example.test/advice --rights 'Fixture rights'
python -m argos knowledge source-approve public-fixture
python -m argos knowledge source-list
python -m argos knowledge source-show public-fixture
python -m argos knowledge sync-public public-fixture --manifest ./fixture/manifest.json --dry-run
python -m argos knowledge sync-public public-fixture --manifest ./fixture/manifest.json \
  --release fixture-1 --apply "$PLAN_SHA256"
python -m argos knowledge maintenance-report public-fixture
python -m argos knowledge index-verify
```

Les options `--model` et `--model-digest` de la publication permettent
de demander le rafraîchissement vectoriel avec un modèle local existant.
La qualification de ce lot utilise un fournisseur d’embeddings simulé
et n’effectue aucun appel au modèle génératif.

## Qualification et passage à l’échelle

Les tests ciblés couvrent la migration v6, l’intégrité des originaux,
les échéances, la prévisualisation, les versions, l’obsolescence, le
retrait, les écritures concurrentes, l’interruption, l’atomicité avec
embeddings simulés et le rafraîchissement d’une vue NumPy chaude.
Une reconstruction FTS5 puis vectorielle est vérifiée. L’inventaire du
vault provient exclusivement des fixtures. Les deux runtimes Ollama et
les huit manifestes de modèles restent préservés. Les suites régulières
comptent chacune 1 447 tests réussis et 121 ignorés sous Python 3.12 et
3.14. Ruff, formatage, Pyright, le verrou uv et `git diff --check` passent.

Mesures locales sans embeddings, sur trois répétitions par taille,
en Python 3.14. La modification change une note et en retire une autre.
Les durées sont des médianes. Le pic RSS observé pour le processus de
mesure est de 54,2 Mio, imports compris.

| Notes en entrée | Opération | Analyse des fichiers | Plan | Publication | Taille SQLite |
| ---: | --- | ---: | ---: | ---: | ---: |
| 100 | Initiale | 86,51 ms | 2,87 ms | 334,86 ms | 1,06 Mio |
| 100 | Inchangée | 84,47 ms | 4,33 ms | 10,31 ms | 1,06 Mio |
| 100 | Modifiée et retirée | 68,44 ms | 7,55 ms | 18,57 ms | 1,06 Mio |
| 512 | Initiale | 461,98 ms | 11,57 ms | 1 683,94 ms | 4,78 Mio |
| 512 | Inchangée | 407,88 ms | 19,68 ms | 43,74 ms | 4,78 Mio |
| 512 | Modifiée et retirée | 422,53 ms | 24,68 ms | 79,52 ms | 4,78 Mio |

Le coût du scan dépend du nombre et de la taille des notes, car la
comparaison vérifie les empreintes même lors d’un passage inchangé.
La publication est bornée à 512 entrées et 64 Mio d’originaux par
manifeste, 128 Mio de normalisations préparées et 100 000 fragments
préparés. Une source peut retenir jusqu’à 4 096 identités gérées.
La taille disque dépend de l’historique et des caches conservés. La
qualification ne couvre pas un vault réel ni un corpus public distant.

## Bilan consolidé de M3.5

| Brique | Livrée et qualifiée | Limites et suites |
| --- | --- | --- |
| Données et ingestion | Stockage local par UID et collection, formats Markdown, TXT et JSON, provenance, versions, normalisation et fragments. | Le partage organisationnel et la purge physique gardent leur propre politique. |
| Récupération | SQL exact, FTS5/BM25, NumPy exact, cache versionné, préfiltrage par collection, repli lexical. | Les recherches lexicales peu sélectives et le chargement froid NumPy restent coûteux à 100 000 fragments ou vecteurs. RRF et reranker sont reportés. |
| Contexte et revue | V1 compatible, V2 extractif borné avec citations épinglées et validation des propositions typées. | La validation sémantique des questions libres, les annotations humaines et la qualification générative restent ouvertes. |
| Mémoire | Intégrée sous les règles UID, mission et snapshot. | Aucun gain après déduplication dans les trois relectures d’archive qualifiées. |
| Maintenance | Lots transactionnels, import Obsidian synthétique, proposition et application d’un manifeste public simulé. | Fournisseurs publics réels, exécution planifiée, rétention bornée et échelle supérieure à valider séparément. |

Sur 100 000 vecteurs synthétiques sans filtre large, le p95 chaud du
parcours de production hors embedding de requête était de 76,3 ms en
512 dimensions et 109,8 ms en 768 dimensions. Le chargement initial
vérifié approche 11 s. Ces résultats historiques ne mesurent pas le coût
d’une acquisition distante. Le pilote génératif n’a pas franchi les seuils
des [essais M3.5.6](M356_RAG_EVALUATION.md). La
[validation par proposition](M3562_PROPOSITION_VALIDATION.md) rétablit cinq
réponses exactes sur onze cas répondables, avec six cas libres toujours
ouverts. Les jeux restent insuffisants pour autoriser le pilote génératif.

La configuration stable est **Qwen3 4B, Qwen3-Embedding 512, NumPy exact,
SQL/FTS5 et V2 extractif avec propositions typées**. Le profil d’usage
conserve le cloisonnement et les validations indépendantes du modèle.
