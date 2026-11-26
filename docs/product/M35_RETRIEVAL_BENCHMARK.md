# M3.5-E — Embeddings et récupération hybride

Banc d'essai local sur `feat/m35-retrieval-benchmark`, depuis `4b117e5`.
Il compare des passages documentaires et leurs références au niveau document.
Les cas, index et scripts du banc restent hors du runtime produit.

## Protocole et provenance

- **Corpus réel.** 38 pages MDN en anglais, figées sur
  `42994d9657fd9771d5c45579521d947ba5babc05`. Le
  [manifeste](../../benchmarks/retrieval/sources.json) fixe source, attribution et
  SHA-256. Les fichiers et la licence originale restent sous
  `data/knowledge/m35-retrieval/corpus/`. La prose MDN est sous CC BY-SA 2.5
  et les exemples suivent les conditions du fichier de licence amont.
  [Licence MDN](https://github.com/mdn/content/blob/42994d9657fd9771d5c45579521d947ba5babc05/LICENSE.md)
- **Jugements.** 20 requêtes de réglage et 134 finales, écrites avant les
  résultats. Leurs textes et documents jugés pertinents sont disjoints entre
  jeux. Le jeu final contient 122 requêtes avec résultat pertinent et 12 sans
  réponse, avec négatifs dans et hors domaine. Il couvre identifiants,
  requêtes techniques anglaises, français vers anglais, paraphrases,
  ambiguïtés et en-têtes obsolètes. Les degrés 2/1 indiquent la référence
  principale et une référence secondaire pertinente. Un seul annotateur,
  jugements au niveau document et fournisseur unique. Les cas obsolètes
  confrontent les recommandations modernes aux références dépréciées.
- **B0.** SQLite FTS5, tokenisation `unicode61`, opérateurs OR littéraux
  et titre pondéré. Les résultats sont regroupés par document avant le
  calcul des métriques. Longueur maximale commune de 1 024 caractères
  par fragment. Le mode structurel conserve des sections avec coupe de
  secours, le récursif préfère les séparateurs, le fixe découpe le texte
  continu. Aucun recouvrement.
- **B1–B5.** Cosinus exact sur vecteurs float32 normalisés, avec le même
  backend NumPy. B4 utilise RRF à poids égaux, constante 60, sur les rangs
  de documents. B5 tronque puis renormalise les sorties des modèles
  Matryoshka. BGE-M3 est évalué en dense natif uniquement. Les seuils
  d'abstention maximisent la moyenne du rappel positif et du rappel négatif
  sur le jeu de réglage. Le test final rapporte les deux valeurs.
- **Charge.** 100 000 vecteurs synthétiques float32, dimension 512, graine
  3515 et 64 requêtes pour les trois moteurs exacts. Une charge FTS
  synthétique utilise 100 000 courts fragments à vocabulaire répétitif.
  La qualité documentaire est mesurée uniquement sur le corpus MDN.
  La première latence est celle de la première recherche après construction.
  Le froid dense force le déchargement Ollama entre requêtes, sans purge du
  cache disque OS. La RAM du serveur est échantillonnée via le RSS de son
  arbre de processus et la VRAM via `nvidia-smi`; le RSS additionné peut
  compter plusieurs fois les pages partagées.

## Environnement et modèles

WSL présente 15 Gio de RAM, 16 CPU logiques (Ryzen 7 7735HS) et une RTX 4060
Laptop avec 8 188 Mio de VRAM. Le volume de travail avait 817 Gio disponibles.
Les mêmes NumPy 2.5.5, sqlite-vec 0.1.9 et FAISS CPU 1.16.0 ont été installés
et exercés dans des environnements dédiés Python 3.12.15 et 3.14.6.
Les dépendances produit restaient intactes.

Le dépôt et le runtime Ollama 0.11.11 existants ont été conservés. Qwen3 a été
refusé par le registre avec HTTP 412. Le runtime parallèle Ollama 0.40.18
est issu de la [release officielle](https://github.com/ollama/ollama/releases/tag/v0.40.18),
archive Linux amd64 au SHA-256
`b82649006cb5b54ed1237fa2d1a26a7f939a4fd03150033759acbff7ff315adf`.
Le dépôt d'embeddings est `data/ollama/m35-retrieval/models/`.

| Candidat | Tag Ollama | Format vérifié | Dimensions évaluables | Instructions |
| --- | --- | --- | --- | --- |
| Qwen3-Embedding 0.6B | `qwen3-embedding:0.6b` | Q8_0, Apache-2.0 | 256 / 512 / 1024 | Instruction de recherche côté requête. Titre et texte côté document. [Fiche Qwen](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B) |
| EmbeddingGemma | `embeddinggemma:300m` | BF16, Gemma Terms | 256 / 512 / 768. 1024 indisponible. | Préfixes de recherche et de document prescrits par Google. [Fiche Google](https://ai.google.dev/gemma/docs/embeddinggemma/model_card), [conditions](https://gemma.ai/resources/terms/) |
| BGE-M3 | `bge-m3:567m` | F16, MIT | 1024. 256/512 hors des dimensions documentées. | Requête sans instruction. Ollama expose ici la sortie dense. [Fiche BAAI](https://huggingface.co/BAAI/bge-m3) |

## Reproduire les essais

Depuis le clone, initialiser les chemins et reconstruire le corpus épinglé.
Cette étape seule récupère les documents publics. Conserver un dossier de
sortie neuf pour chaque exécution.

```bash
root="$(scripts/argos data init)"
python -m benchmarks.retrieval.corpus --out "$root/knowledge/m35-retrieval/corpus"
uv venv --python 3.14 "$root/qualification/m35-venv"
runner="$root/qualification/m35-venv/bin/python"
uv pip install --python "$runner" -r benchmarks/retrieval/requirements.txt
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
```

Avec les trois tags déjà présents sous la racine résolue, lancer le serveur
de qualification depuis un terminal dédié.

```bash
root="$(scripts/argos data init)"
benchmark="$root/ollama/m35-retrieval"
OLLAMA_MODELS="$benchmark/models" OLLAMA_HOST=127.0.0.1:11536 \
  OLLAMA_NO_CLOUD=1 OLLAMA_NOPRUNE=1 OLLAMA_MAX_LOADED_MODELS=1 \
  OLLAMA_NUM_PARALLEL=1 "$benchmark/runtime-0.40.18/bin/ollama" serve
```

`ARGOS_DATA_HOME` personnalise cette racine via `data init`. Un
changement de racine exige que les artefacts y soient déjà présents.
Le binaire parallèle est lancé explicitement et le lanceur principal
`scripts/llm/ollama-local` garde `ollama/runtime` et `ollama/models`.
Utiliser `benchmarks.retrieval.sample_host --pid PID --out FICHIER.jsonl`
dans un autre terminal pendant chaque mesure.

```bash
corpus="$root/knowledge/m35-retrieval/corpus"
out="$root/qualification/m35-recheck"
"$runner" -m benchmarks.retrieval.run --corpus "$corpus" \
  --out "$out/lexical" --modes fixed structural recursive
"$runner" -m benchmarks.retrieval.run --corpus "$corpus" \
  --out "$out/models" --port 11536 \
  --models qwen3-embedding:0.6b embeddinggemma:300m bge-m3:567m
for engine in numpy sqlite-vec faiss lexical; do
  "$runner" -m benchmarks.retrieval.scale --backend "$engine" --out "$out/scale/$engine"
done
"$runner" -m benchmarks.retrieval.checks --compare "$out/scale" --out "$out/checks.json"
```

Pour comparer les index sur les mêmes vecteurs réels, ajouter
`--real CHEMIN-vers-vectors.npz --dimension DIMENSION` aux trois commandes
`scale` vectorielles. Les sorties conservent la configuration, les empreintes,
les fragments, les requêtes, les jugements, les rangs, les latences unitaires et
les vecteurs. La mesure séquentielle se rejoue avec `python -m
benchmarks.retrieval.pipeline_probe --run CHEMIN --model embeddinggemma:300m
--out FICHIER.json`, où `CHEMIN` contient les sorties récursives de Gemma.
Les résultats de cette campagne sont sous
`data/qualification/m35-retrieval/`.

## Résultats lexicaux et charge

| Découpage FTS5 | Fragments | R@5 | R@10 | P@5 | MRR | nDCG@10 | Identifiant top-1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Fixe | 294 | 75,5 % | 82,8 % | 16,2 % | 0,652 | 0,681 | 96,3 % |
| Structurel | 514 | 74,7 % | 84,0 % | 16,1 % | 0,648 | 0,680 | 96,3 % |
| Récursif | 530 | 75,8 % | 84,0 % | 16,4 % | 0,652 | 0,683 | 96,3 % |

Le récursif apporte 1,2 point de rappel à 10 contre le fixe sur ce corpus,
avec 80 % de fragments supplémentaires. Son p95 à chaud est de 2,55 ms
contre 2,13 ms pour le fixe. Le p95 après réouverture d'une connexion SQLite
est de 3,26 ms pour le récursif. La comparaison ne mesure pas la précision
des frontières de passages, car les jugements sont au niveau document.

| Moteur sur 100 000 fragments synthétiques | Construction | 1re requête | p50 / p95 chauds | Ajout d'une ligne | RSS crête | Disque |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| NumPy | 0,06 ms | 16,48 ms | 16,42 / 19,35 ms | 39,61 ms | 432,7 Mio | 195,3 Mio |
| FAISS FlatIP CPU | 657 ms | 17,28 ms | 15,79 / 19,87 ms | 321,36 ms | 647,4 Mio | 195,3 Mio |
| sqlite-vec cosinus | 7,09 s | 209,46 ms | 168,91 / 183,25 ms | 19,24 ms | 433,1 Mio | 198,5 Mio |
| FTS5/BM25 | 850 ms | 224,54 ms | 229,88 / 344,60 ms | 13,14 ms | 44,0 Mio | 9,5 Mio |

Les trois moteurs vectoriels ont rendu les mêmes ensembles de 10 voisins
pour les 64 requêtes synthétiques. La construction NumPy réutilise le
tableau déjà normalisé. Les temps de construction excluent la génération
et la sérialisation des vecteurs. NumPy recopie ici son tableau pour l'ajout,
alors que sqlite-vec effectue une écriture transactionnelle. Les RSS incluent
le processus de mesure et les tableaux de départ. Le jeu FTS à vocabulaire
répétitif génère de nombreuses correspondances OR et montre un cas défavorable
pour cette requête. Il ne constitue pas une comparaison de qualité avec les
vecteurs synthétiques.

Le test de préfiltrage a placé un fragment privé exactement au point de la
requête vectorielle. Les trois moteurs l'ont exclu en construisant l'index
sur les deux fragments autorisés. FTS exclut le même marqueur. Sur les deux
Python, 25 indisponibilités locales simulées ont rendu exactement la liste
lexicale. Ces essais qualifient le préfiltrage du banc et le repli sur refus
immédiat. Ils ne qualifient pas l'authentification multi-utilisateur ni la
latence lors d'un délai réseau complet.

## Résultats documentaires denses et hybrides

Découpage récursif, 530 fragments. Les métriques de classement excluent
les 12 requêtes sans réponse. La colonne « Sans réponse » compte les
abstentions correctes et la colonne « Réponses gardées » le nombre de requêtes
positives acceptées par le seuil appris sur le jeu de réglage.

| Configuration | R@5 | R@10 | P@5 | MRR | nDCG@10 | ID top-1 | Sans réponse /12 | Réponses gardées /122 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| B0 FTS5 | 75,8 % | 84,0 % | 16,4 % | 0,652 | 0,683 | 96,3 % | 9 | 73 |
| B1 Qwen3 1024 | 95,1 % | 99,2 % | 20,7 % | 0,831 | 0,859 | 100 % | 7 | 121 |
| B2 EmbeddingGemma 768 | 98,4 % | 98,4 % | 21,3 % | 0,866 | 0,888 | 100 % | 10 | 118 |
| B3 BGE-M3 1024 | 93,4 % | 98,4 % | 20,2 % | 0,835 | 0,863 | 100 % | 12 | 96 |
| B4 RRF Qwen3 | 89,8 % | 95,1 % | 19,5 % | 0,744 | 0,785 | 96,3 % | 8 | 100 |
| B4 RRF EmbeddingGemma | 89,8 % | 94,3 % | 19,5 % | 0,766 | 0,801 | 96,3 % | 3 | 97 |
| B4 RRF BGE-M3 | 89,3 % | 95,1 % | 19,3 % | 0,773 | 0,808 | 100 % | 3 | 108 |
| B5 Qwen3 512 | 93,9 % | 100 % | 20,3 % | 0,830 | 0,864 | 100 % | 6 | 121 |
| B5 Qwen3 256 | 92,2 % | 98,8 % | 19,8 % | 0,785 | 0,824 | 96,3 % | 6 | 120 |
| B5 EmbeddingGemma 512 | 97,1 % | 98,4 % | 21,0 % | 0,860 | 0,881 | 100 % | 9 | 115 |
| B5 EmbeddingGemma 256 | 97,1 % | 98,4 % | 21,0 % | 0,819 | 0,851 | 100 % | 12 | 106 |

Les trois modèles natifs obtiennent un rappel à 10 de 100 % sur les 31
requêtes françaises vers le corpus anglais. Aucune mesure français vers
français ni validation indépendante des jugements n'a été réalisée. Le
banc compare les artefacts réellement disponibles, avec leurs quantifications
différentes.

| Modèle | Indexation / débit | Chaud p50 / p95 | Froid p50 / p95 | RSS serveur crête | VRAM Ollama / pic GPU | Cache 530 / édition d'un fragment |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3 | 20,68 s / 25,63 vect./s | 30,63 / 45,98 ms | 4,59 / 6,39 s | 714 Mio | 1 172 / 1 289 Mio | 14,76 / 55,96 ms |
| EmbeddingGemma | 80,65 s / 6,57 vect./s | 31,16 / 56,73 ms | 5,80 / 5,89 s | 1 251 Mio | 654 / 787 Mio | 18,58 / 68,97 ms |
| BGE-M3 | 121,72 s / 4,35 vect./s | 31,23 / 69,93 ms | 5,95 / 6,51 s | 1 469 Mio | 657 / 789 Mio | 19,49 / 45,26 ms |

L'indexation inclut le premier chargement du modèle. Une compilation ou
initialisation GPU a ralenti les premiers chargements de certains candidats.
Les débits ci-dessus sont muraux et ne comparent pas les noyaux à état égal.
Le froid dense repose sur cinq requêtes après déchargement et mesure l'appel
d'embedding. Le chaud additionne les étapes effectivement chronométrées
pour 134 requêtes. Un essai hybride séquentiel distinct mesure le parcours
complet avec EmbeddingGemma, p50/p95 de 33,25/51,41 ms à chaud (20 mesures)
et 4,67/5,00 s après déchargement (4 mesures). Avec ces petits échantillons,
le p95 froid correspond au maximum observé.

Le modèle a disparu de `/api/ps` après chaque série. La mémoire GPU échantillonnée
est revenue à 0 Mio pour Qwen et Gemma, et à 9 Mio en dernière lecture BGE.
Les caches SQLite d'embeddings occupent 2,14 Mio pour Gemma et 2,39 Mio pour
Qwen et BGE. Ces fichiers gardent les sorties natives. Les dimensions réduites
sont évaluées avec les mêmes vecteurs tronqués puis renormalisés.
Pour 16 fragments, un lot unique a pris 529/490/372 ms (Qwen/Gemma/BGE),
contre 656/685/525 ms pour 16 appels unitaires. Le test d'édition a produit
un seul nouveau vecteur malgré une répétition du fragment modifié. Les données
MDN n'ont produit aucun doublon exact intra-document. Le dédoublonnage du
banc a été vérifié sur fixture, avec conservation de la provenance.

### Découpage avec EmbeddingGemma 768

| Mode | Fragments | R@5 | R@10 | nDCG@10 | Abstentions correctes /12 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fixe | 294 | 97,5 % | 99,2 % | 0,905 | 11 |
| Structurel | 514 | 98,4 % | 98,4 % | 0,894 | 10 |
| Récursif | 530 | 98,4 % | 98,4 % | 0,888 | 10 |

Le fixe gagne en classement documentaire pour Gemma sur ce jeu et produit
moins de fragments. La comparaison ne mesure pas la qualité des limites de
passages. Le mode structurel garde un intérêt si une citation doit rejoindre
une section précise. Une nouvelle sélection indépendante sera nécessaire
avant de figer le découpage du produit.

### Moteur exact sur les mêmes vecteurs réels

Sur les 530 vecteurs EmbeddingGemma ramenés à 512 dimensions, les trois
moteurs ont retrouvé les mêmes ensembles top‑10 pour les 154 requêtes.
P95 à chaud de la recherche seule, NumPy 0,100 ms, FAISS 0,124 ms et
sqlite-vec 1,987 ms. La charge à 100 000 fragments utilise les données
synthétiques décrites plus haut. L'inférence de 100 000 embeddings réels
et un index approximatif n'ont pas été testés.

## Décision expérimentale

- **Retenir EmbeddingGemma 768 pour un prochain pilote** si les conditions
  Gemma sont acceptables. Il a le meilleur nDCG et le meilleur compromis
  d'abstention de la campagne à découpage commun, avec 654 Mio de VRAM
  d'après Ollama. **Qwen3 512** est l'alternative Apache-2.0 si le débit,
  la latence à chaud ou le rappel à 10 priment. EmbeddingGemma 512 reste
  un compromis de stockage, avec un nDCG inférieur de 0,008 et le même
  rappel à 10 sur ce jeu. BGE-M3 dense est écarté pour le premier pilote,
  malgré ses 12 abstentions correctes, car son seuil écarte 26 requêtes
  positives et son coût d'indexation est supérieur.
- **Retenir NumPy exact**. FAISS FlatIP n'améliore pas le p95 synthétique
  et utilise davantage de RAM sur cette machine. sqlite-vec apporte une
  insertion transactionnelle mais ralentit nettement cette recherche.
  Garder SQLite FTS5 pour le lexical et comparer de nouveau si la taille,
  la concurrence ou la persistance vectorielle deviennent déterminantes.
- **Garder un parcours dense prioritaire et FTS5 en secours**. RRF à poids
  égaux dégrade le rappel, le classement et souvent l'abstention pour les
  trois modèles. Une voie lexicale ciblée sur les identifiants, ou une fusion
  pondérée, pourra être évaluée sur un nouveau jeu final. Aucun reranker
  n'a été exécuté. Les défauts mesurés justifient d'abord de qualifier la
  stratégie de fusion et l'abstention sur davantage de négatifs.
- **Retenir les lots de 16 pour ce banc**, le cache lié au digest du modèle
  et au texte préparé, le recalcul local d'un fragment modifié et le
  préfiltrage des collections. Le benchmark mesure l'ajout côté index et
  le recalcul d'une édition. La persistance complète d'une modification,
  son retrait transactionnel et les ACL de production restent à concevoir.

## Validation et preuves locales

- `pytest -q -o faulthandler_timeout=30` donne 1 276 réussites et 122 ignorés
  sous Python 3.12 et 3.14. Les sept tests du lot passent sur chaque Python
  avec les dépendances dédiées, dont le parcours dense simulé ignoré dans
  la suite standard. Ruff, formatage, Pyright et `git diff --check` passent.
- Les empreintes et tailles des couches des trois embeddings sont vérifiées
  dans `host/model-lock.json`. Qwen publie sa licence Apache-2.0 dans sa
  fiche amont. Le manifeste Ollama local du tag Qwen et le digest annoncé
  par l'API sont conservés séparément. Les cinq manifestes LLM d'origine
  sont identiques avant/après et l'inventaire des blobs d'origine est inchangé.
- Les répertoires `real-*`, `gemma-chunking`, `scale-100k-*`, `scale-real` et
  `host` documentent mesures brutes et versions. Les essais interrompus
  antérieurs restent identifiés par `attempt-*` et `ollama-01111`.


## Consolidation du 26 novembre 2026

- **Reproductibilité.** Les 38 sources MDN et leur fichier de licence
  correspondent au manifeste. Les 15 fichiers de configuration, déclarations
  de sources et jugements copiés dans les cinq campagnes correspondent
  aux entrées versionnées. Le replay hors ligne a reconstruit huit index
  BM25 et reproduit rangs, métriques et abstention dans 18 configurations
  denses ou hybrides à partir des vecteurs conservés. Les scores cosinus
  concordent à la tolérance float32 du replay. Les 64 ensembles top‑10
  synthétiques ont été reproduits avec NumPy et comparés aux trois mesures
  archivées. Les 154 ensembles top‑10 réels ont été recalculés sur les
  trois moteurs. Ce contrôle porte sur le classement, pas sur la stabilité
  des latences ou des vecteurs recalculés sur un autre hôte.
- **Dépôts Ollama.** Les deux serveurs ont été lancés sur loopback avec
  des répertoires de modèles distincts. Le 0.11.11 a annoncé ses cinq LLM
  et le 0.40.18 ses trois embeddings. Les tailles et SHA-256 des 34 blobs
  référencés concordent avec les manifestes. Le binaire d'origine et
  l'archive du runtime parallèle correspondent à leurs empreintes de
  référence. Les serveurs ont été arrêtés après l'inventaire. Aucun
  modèle téléchargé, supprimé ou chargé pendant cette consolidation.
- **Licences.** Le fichier MDN épinglé confirme CC BY-SA 2.5 pour la
  prose, CC0 pour les exemples ajoutés depuis le 20 août 2010 et MIT
  pour les exemples antérieurs. Conserver les attributions, références,
  notices et conditions applicables en cas de redistribution.
  [Licence MDN](https://github.com/mdn/content/blob/42994d9657fd9771d5c45579521d947ba5babc05/LICENSE.md)
- **Modèles.** Les notices Ollama identifient MIT pour BGE-M3 et
  DeepSeek-R1 7B, Apache-2.0 pour Qwen2.5 et Qwen3 de génération, et
  Gemma Terms pour EmbeddingGemma et Gemma 3. Le paquet Ollama de
  Qwen3-Embedding ne contient pas de couche de licence. La fiche
  officielle du modèle indique Apache-2.0. Le pilote EmbeddingGemma
  dépend des conditions et restrictions d'usage Gemma. Cette revue
  ne vaut pas décision de redistribuer les poids ou le runtime.
  [Fiche Qwen](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B),
  [Fiche BAAI](https://huggingface.co/BAAI/bge-m3),
  [Conditions Gemma](https://gemma.ai/resources/terms/)
- **Dépendances du banc.** Les métadonnées locales concordent sous
  Python 3.12 et 3.14. NumPy 2.5.5 est sous BSD-3-Clause, avec des
  notices pour les composants inclus, notamment OpenBLAS et le runtime
  GCC. FAISS CPU 1.16.0 est sous MIT avec ses notices tierces.
  sqlite-vec 0.1.9 indique MIT et Apache-2.0. packaging 26.4 indique
  Apache-2.0 ou BSD-2-Clause. Ces versions restent dans les environnements
  du banc et leurs notices restent avec les paquets installés.
  [NumPy](https://github.com/numpy/numpy/blob/main/LICENSE.txt),
  [FAISS](https://github.com/facebookresearch/faiss/blob/main/LICENSE),
  [sqlite-vec](https://github.com/asg017/sqlite-vec),
  [packaging](https://github.com/pypa/packaging/blob/main/LICENSE)
- **Git.** La revue des fichiers suivis et des nouveaux blobs n'a trouvé
  ni corpus récupéré, ni modèle, ni index, ni résultat privé.
  Les TSV suivis contiennent les requêtes et jugements synthétiques
  créés pour le banc. Les fichiers d'exécution restent dans les zones
  ignorées de `ARGOS_DATA_HOME`.

### Choix provisoires du pilote

EmbeddingGemma 768 sous réserve des conditions Gemma, Qwen3 512 en
alternative, et NumPy exact. Prévoir FTS5 en secours et une recherche exacte
SQL pour les identifiants. La recherche exacte SQL est un choix du pilote
à qualifier séparément. La fusion RRF reste hors du périmètre initial.
Conserver les lots de 16, le cache versionné et l'indexation incrémentale.
Le préfiltrage des collections est obligatoire, avec qualification future
des droits et du cycle de vie complet des index.

Ces choix reposent sur un corpus anglais d'un seul éditeur, des jugements
documentaires d'un seul annotateur, douze requêtes négatives, un hôte WSL et
une charge de 100 000 fragments synthétiques. Un corpus plus varié et un jeu
final indépendant devront valider les citations au niveau passage, la
recherche exacte SQL et les décisions d'abstention du pilote. La migration
définitive d'Ollama reste une décision distincte.
