# M3.5.8 — Consolidation du Knowledge Engine

La consolidation M3.5.8 est présente sur main au SHA
`74b3221f8120a6cd0d3365eff2a13b2a35d74280`. Le bilan historique de la
branche part de `037c203` et porte sur le moteur documentaire et la
restitution extractive. Le pilote génératif reste non qualifié. La suite
figure dans le [lot M3.5.9](M359_WORKFLOW_QUALIFICATION.md).

## Responsabilités et interfaces

| Composant | Responsabilité | Frontière vérifiée |
| --- | --- | --- |
| `argos.backend.knowledge` | `KnowledgeStore` et registre pour les sources, versions et originaux. Normalisation et découpage avant publication. `SQLiteKnowledgeRetriever`, `NumPyKnowledgeRetriever` et `RetrievalRouter` pour les passages. | Modules indépendants de la revue web, de la mémoire de mission et des outils. Une collection et un ensemble d’autorisations explicites par lecteur. |
| `argos.backend.consultation` | `Budget`, enveloppe de contexte, contrat `Selector` et restitution V2. `Attribution` et `RecordedHTTPStatus` vérifient des propositions déterministes. | Données, instructions et autorisations distinctes. Les extraits ne déterminent aucun droit. L’attribution textuelle et le constat d’archive ont des portées différentes. |
| Adaptateurs de revue | `ReviewContextV2` lie le snapshot, les observations vérifiées, la mémoire admissible et les collections. Le journal supervise les tentatives et leur acceptation. | Les besoins spécifiques à la mission restent dans l’adaptateur. V1 et les journaux existants gardent leur contrat. |
| Maintenance | `Maintenance.preview/apply`, sélection Obsidian et `PublicProvider` produisent et vérifient des manifestes. | La publication réutilise les primitives d’ingestion, d’approbation et de retrait. Le fournisseur public testé lit des fixtures locales. |

Le découpage permet de réutiliser Knowledge et Consultation dans une autre
spécialisation en fournissant un adaptateur de contexte et de vérification.
Les contrats publics sont typés aux frontières principales. Plusieurs résultats
de CLI et de journal restent des dictionnaires, et le routage compose les
lecteurs concrets. Les projections SQL, FTS5 et NumPy répondent à des usages
distincts. Leur cohérence dépend de l’autorité de SQLite et mérite les tests
de retrait, de réindexation et d’invalidation existants.

## Qualification de la chaîne documentaire

- Le test `test_private_note_maintenance_through_extractive_review` importe
  une note Markdown synthétique avec frontmatter et fins de ligne CRLF.
  Il vérifie la conservation de l’original, le repère de ligne et le titre
  de section, la provenance, l’inertie d’une transclusion et l’impossibilité
  de lire depuis la collection globale. Il construit une vue NumPy avec
  un fournisseur simulé et valide la citation en V2 avec un sélecteur
  simulé. Après modification, l’ancienne référence est refusée et le
  mode automatique récupère la nouvelle version via FTS5.
- Le CLI a aussi été exécuté depuis un répertoire de travail distinct,
  avec une archive Git propre et un `ARGOS_DATA_HOME` temporaire.
  Initialisation, import, approbation, recherche, retrait et vérification
  FTS5 passent sans dépendre de l’arborescence locale des données.
- Les suites existantes couvrent aussi le CLI et V1, les formats TXT et
  JSON, les autres découpeurs, les droits avant lecture, la révocation
  pendant l’analyse et avant l’acceptation, les écritures concurrentes,
  l’échec d’un lot et sa reprise. Les documents et les champs de provenance
  restent des données non fiables. La conservation des statuts et
  l’interdiction d’interpréter une citation comme implication sémantique
  bornent la restitution extractive.
- La matrice utilise de vrais schémas historiques créés avec le code de
  `9bb08c1` (v1), `518a939` (v2), `605e45a` (v3), `d8f0eeb` (v4),
  `40f3c6e` (v5) et `037c203` (v6). Les six cas passent sous chacun des
  deux interpréteurs. Contrôles après initialisation répétée sur v6.
  SQLite et clés étrangères valides, même version publiée et mêmes
  octets originaux, SQL exact et FTS5 valides, vecteurs v4 et ultérieurs
  vérifiés. En v1, la réingestion explicite reconstruit la projection
  pour les originaux hérités sans changer leur identifiant de version.
- Les contrôles d’accès s’appuient sur l’UID effectif, une base par
  collection, des permissions privées et le refus des liens dans les
  chemins sensibles. Le retrait retire les associations d’index et
  change la génération. Une ancienne vue NumPy est écartée à la lecture
  suivante et une citation retirée ne se résout plus. Les originaux
  conservés exigent toujours un accès autorisé à la collection.

### Contrôles des actifs et de Git

Les manifestes d’Ollama correspondent aux huit empreintes de référence.
Les 34 blobs de configuration et de modèle référencés correspondent à leur
taille et à leur SHA-256. Les deux binaires locaux 0.11.11 et 0.40.18
conservent leurs empreintes avant et après la qualification. Le contrôle
SQLite des données OSINT locales a été exécuté en lecture seule. Les
migrations ont utilisé des fixtures isolées. Aucun nouvel essai de
génération, téléchargement ou accès au vault de l’opérateur.

L’arbre suivi ne contient sous `data/` que le README et les marqueurs
de dossiers. L’inspection de l’arbre et des objets ajoutés depuis
`main` ne détecte ni modèle, base, cache vectoriel ou index ni données
d’exploitation privées. Gitleaks 8.30.1, déjà installé, ne remonte aucun
secret dans l’arbre suivi ni dans le delta historique analysé. Les journaux
de qualification et scripts d’inspection locaux sont sous
`data/qualification/m358/`, ignoré par Git.

## Résultats et statut M3.5

| Contrôle final | Résultat |
| --- | --- |
| Python 3.12.15, suite régulière complète | 1 448 réussites, 121 ignorés, 135,76 s |
| Python 3.14.6, suite régulière complète | 1 448 réussites, 121 ignorés, 132,12 s |
| Ruff, formatage, Pyright, `git diff --check`, liens locaux modifiés | Réussis |

Les suites ont été exécutées avec `python -m pytest -q -o faulthandler_timeout=30`.
Le premier lancement sous `umask 077` avait fait échouer deux tests qui
construisent volontairement un répertoire accessible au groupe ou aux
autres. Le lancement final sous `umask 022` valide ces fixtures sans
changement applicatif. Les essais hôte optionnels ignorés gardent leur
statut.

| Statut | Portée |
| --- | --- |
| Livré et qualifié localement | Fondations et migrations, ingestion, découpage et citations de passages, SQL exact, FTS5, recherche dense exacte, V2 extractif, maintenance transactionnelle et import Obsidian synthétique. |
| Livré avec qualification bornée | Revue supervisée compatible V1, embeddings locaux et synchronisation publique par fixtures. La qualification ne couvre pas le partage organisationnel, un fournisseur public réel ni le déploiement multi-utilisateur. |
| Expérimental | Verdicts génératifs libres, validation sémantique par modèle et profils matériels du pilote. Aucun seuil historique n’a été recalibré pour cette consolidation. |
| Reporté | Connecteurs publics réseau, partage organisationnel, rétention physique, nouvelles stratégies de classement et décisions sur un meilleur appui des questions ouvertes. |

La configuration de référence reste Qwen3 4B, Qwen3-Embedding 512, SQL
exact, NumPy et repli FTS5, avec le contrat V2 extractif et ses propositions
typées. Les comparaisons M3.5.6 mesurent 47,8 % de verdicts exacts avec le
LLM seul et 81,7 % avec RAG sur 115 cas. Les seuils absolus n’ont pas été
atteints et les annotations n’ont pas de validation humaine indépendante.
Les trois replays d’archive ne montrent aucun ajout de la mémoire après
déduplication. En M3.5.6.2, V2 résout correctement cinq des onze cas
répondables et laisse les six autres sans réponse. Les rapports
[M3.5.6](M356_RAG_EVALUATION.md) et
[M3.5.6.2](M3562_PROPOSITION_VALIDATION.md) détaillent ces résultats.

Les mesures historiques à 100 000 vecteurs donnent un p95 à chaud de
76,3 ms en 512D et 109,8 ms en 768D dans la collection autorisée.
Le premier chargement vérifié approche 11 s au p95 et un filtre large
porte le p95 à 624 ms ou 643 ms selon la dimension. Le test de maintenance
de 512 notes mesure 1,68 s de publication initiale et 79,52 ms pour une
modification avec un retrait, sans embeddings. Ces mesures n’ont pas été
refaites pour M3.5.8. Voir la [spécification](KNOWLEDGE_ENGINE_SPEC.md)
et le [bilan de maintenance](M357_KNOWLEDGE_MAINTENANCE.md).

## Risques résiduels et historique d’intégration

- Les collections partagent le domaine de confiance de leur UID Unix. Il
  n’existe pas de transaction entre le snapshot de mission, la mémoire et
  les collections documentaires. Une modification concurrente peut
  imposer de reprendre une revue malgré la disponibilité des autres
  éléments. La synchronisation avec recalcul vectoriel atomique conserve
  le verrou SQLite pendant le lot borné.
- La reconstruction à froid, les filtres larges et la RAM à plusieurs
  générations limitent la montée en charge. Les BLOB dédupliqués conservés
  après un retrait logique occupent toujours de l’espace disque.
- La fraîcheur documentaire signale des états et des échéances propres à
  la collection. Une source approuvée peut être incomplète, obsolète ou
  contradictoire. Pour une future qualification générative, faire annoter
  les appuis par des évaluateurs indépendants et conserver la mesure
  d’abstention sur les questions répondables.
- Le `main` local et `origin/main` enregistré pointaient tous deux sur
  `eed15b19` au début de l’audit. Les consignes de clôture demandaient une
  intégration par fast-forward et le suivi de la CI du SHA publié. Avant
  la première ouverture de collections pré-v6 après intégration, sauvegarder
  puis lancer explicitement
  `python -m argos knowledge init` pour chaque collection et contrôler les
  index avec `knowledge index-verify` et, si la collection utilise des
  vecteurs, `knowledge vector-verify` pour l’espace d’embeddings utilisé.
  Une restauration vers un ancien runtime applicatif nécessite une copie
  compatible du schéma. La campagne historique s’est terminée avant l’intégration.
