# M3.5.6 — Évaluation comparée du RAG

Le [bilan M3.5.6.1](M3561_RAG_RELIABILITY.md) audite les sorties de cette
qualification puis mesure la politique d’appui sur un nouveau jeu.

## Protocole et portée

Le [protocole](../../benchmarks/rag_eval/README.md), les seuils et les jugements
ont été figés au commit `6f721b3` avant la première inférence sur le jeu final.
Le développement comporte huit cas et le final 115 cas bilingues sur 33
passages. Les 25 notices originales ont été attribuées à OWASP, MITRE CWE,
l’IETF, MDN et l’ANSSI. Huit autres notices contrôlent les scénarios
synthétiques. Les fragments correspondent à des paraphrases courtes. Les
jugements portent sur leurs références, avec une seule unité par notice.
Les quatre variantes de chaque famille restent corrélées. Les annotations
proviennent d’un seul assistant et aucune seconde annotation humaine n’a été
faite. Les données M3.5-E sont restées une référence historique.

Les cinq bras utilisent le même Qwen3 4B déjà installé et les mêmes
propositions, sans réglage sur le final. Le verdict généré est oui, non ou
indéterminé, avec une liste facultative de références transmises. A0 peut
répondre depuis sa mémoire paramétrique. Les cas synthétiques d’archives
reçoivent une observation admissible à partir d’A1. Sur les cas documentaires,
les bras A0 à A2 ont généralement le même contexte vide. Le bras mémoire
injecte des doublons de l’observation sur les cas synthétiques. L’effet réel
du Memory Engine est vérifié sur les trois archives locales.

Le coût de récupération des bras A3 et A4 comprend le classement des dix
passages, effectué une seule fois par question puis réutilisé dans la
comparaison appariée. Les six premiers candidats alimentent l’assembleur
V2. L’exercice est en dense strict avec Qwen3-Embedding, sans seuil de cosinus
ni reranker. Les documents déclarés obsolètes sont écartés à l’assemblage.
Les résultats du sélecteur extractif et ceux du verdict généré ont des
barèmes distincts. La qualité d’une explication en prose reste hors de la
mesure.

L’exactitude est la proportion de verdicts annotés correctement. La
pertinence appuyée demande en plus, lorsqu’un fragment pertinent est
annoté, une référence utile. La précision et le rappel des citations
mesurent les passages annotés. Un verdict erroné reste non appuyé même s’il
cite un passage jugé pertinent pour la question. L’absence structurelle de
citations dans A0–A2 est visible dans les métriques de provenance et
n’abaisse pas leur score d’exactitude. L’indicateur de couverture critique
demande un verdict correct et un passage critique ou les deux références
sur un conflit non résolu.

Les digests des modèles, requêtes, passages, empreintes des entrées, mesures
et sorties brutes sont sous `data/qualification/m356/`. Les journaux
privés restent dans `archives/` sous ce répertoire. Aucun fichier de cible
ou résultat brut n’est versionné.

## Rejouer

Démarrer les deux Ollama préinstallés sur la boucle locale, avec le lanceur
Argos pour Qwen3 4B sur 11545 et le runtime parallèle avec ses modèles pour
les embeddings sur 11546. Les deux commandes suivantes se lancent dans des terminaux séparés.

```bash
ARGOS_OLLAMA_PORT=11545 scripts/llm/ollama-local serve
```

```bash
EMBED_ROOT="${ARGOS_DATA_HOME:-$PWD/data}/ollama/m35-retrieval"
OLLAMA_MODELS="$EMBED_ROOT/models" OLLAMA_HOST=127.0.0.1:11546 \
  OLLAMA_NO_CLOUD=1 OLLAMA_NOPRUNE=1 OLLAMA_MAX_LOADED_MODELS=1 \
  OLLAMA_NUM_PARALLEL=1 "$EMBED_ROOT/runtime-0.40.18/bin/ollama" serve
```

Les chemins d’archive et de mémoire ci-dessous désignent les répertoires
existants de l’opérateur. Chaque commande de mesure attend un dossier de
sortie neuf.

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
python -m benchmarks.rag_eval.run --split development --out "$OUT/development"
python -m benchmarks.rag_eval.run --split final --out "$OUT/final"
python -m benchmarks.rag_eval.archives --archives "$ARCHIVES" --memory "$MEMORY" \\
  --data-home "$OUT/final/fixture-data" --out "$OUT/archives"
python -m benchmarks.rag_eval.resources --data-home "$OUT/final/fixture-data" \\
  --out "$OUT/resources"
python -m benchmarks.rag_eval.report "$OUT"
```

La commande de ressources lance et arrête ses propres daemons, sur 11547
et 11548 par défaut. Arrêter les daemons du banc principal avant cette étape
pour mesurer la marge GPU du scénario seul. Le protocole de ressources porte
sur une seule question TLS et trois répétitions par profil. Il échantillonne
la mémoire GPU de la machine et la RAM PSS des deux groupes de processus
Ollama. Les valeurs sont des mesures locales descriptives.

## Verdict généré sur 115 cas

| Bras | Exactitude | Pertinence appuyée | Précision citations | Rappel citations | Affirmations non appuyées | Couverture critique |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A0 LLM seul | 47,8 % | 5,2 % | 0 % | 0 % | 100 % | 0 % |
| A1 état et preuves | 43,5 % | 5,2 % | 6,1 % | 3,6 % | 97,3 % | 4,1 % |
| A2 état, preuves et mémoire | 44,3 % | 5,2 % | 6,2 % | 3,6 % | 97,3 % | 4,1 % |
| A3 état, preuves et RAG | 81,7 % | 67,8 % | 79,3 % | 82,9 % | 32,2 % | 71,4 % |
| A4 état, preuves, mémoire et RAG | 81,7 % | 69,6 % | 79,7 % | 84,7 % | 30,4 % | 71,4 % |

- **Knowledge Engine.** A3 gagne 44 cas nets sur A1, soit +38,3 points.
  A4 gagne 39 cas nets sur A0, soit +33,9 points. Le gain apparié atteint
  le seuil de 5 points. Les deux bras RAG échouent cependant aux seuils de
  85 % d’exactitude, 90 % de précision des citations, 80 % d’abstention
  correcte et 10 % maximum d’affirmations non appuyées. Le seuil de rappel
  des citations de 70 % est franchi.
- **État, preuves et contexte.** A1 perd 5 cas nets sur A0. Sur les six
  questions d’archive ou de contradiction, A0 répond correctement à quatre,
  et A1 à deux. Les 109 autres prompts A0 et A1 sont identiques, avec trois
  divergences de verdict observées malgré la température nulle. Le plan
  maintient les mêmes plafonds et utilise le même assembleur. Il mesure
  l’effet de l’état et des preuves sans isoler celui du gestionnaire de budget.
- **Mémoire.** A2 gagne un cas net sur A1, sans nouvel élément après
  déduplication. Il y a aussi trois divergences de verdict à entrée
  identique pour cette comparaison. A4 rend exactement les mêmes 115
  verdicts qu’A3. Le faible écart de citations ne démontre pas de gain
  d’information propre à la mémoire.
- **Abstention.** A0 s’abstient correctement sur les 8 cas indéterminés,
  mais perd 36 des 107 cas répondables. A1 et A2 couvrent 4 cas indéterminés
  sur 8 et perdent chacun 36 cas répondables. A3 et A4 tranchent sur les
  115 cas, y compris les 8 indéterminés. Les deux conflits ORCHID-41
  donnent des verdicts définitifs alors que les deux durées sont
  présentes dans les candidats disponibles. Sur l’obsolescence LILAC-11,
  A3 et A4 répondent correctement aux deux cas.
- **Injection et références.** Aucun marqueur canari n’est émis ni rendu.
  Le schéma contraint cette sortie. A4 répond correctement à deux des trois
  cas d’injection. Le verdict sur ROTOR-7 est erroné bien qu’il cite la
  notice attendue. A0 émet 62 références à des IDs locaux indisponibles
  et A1 et A2 en émettent respectivement 60 et 59. Le validateur n’en
  rend aucune. A3 et A4 n’émettent aucun ID indisponible.

Les échecs d’A4 incluent 12 cas documentaires ordinaires, majoritairement
des formulations françaises négatives, en plus de l’injection ROTOR-7 et
des 8 cas indéterminés. La pertinence du passage récupéré ne suffit pas à
garantir la lecture de la négation, le lien d’appui ou l’abstention.

| Bras | Tokens médians entrée / sortie | Récupération médiane | Assemblage médian | Génération médiane | Validation médiane |
| --- | ---: | ---: | ---: | ---: | ---: |
| A0 | 179 / 15 | — | 0,06 ms | 428 ms | 0,03 ms |
| A1 | 180 / 15 | — | 0,05 ms | 413 ms | 0,03 ms |
| A2 | 180 / 15 | — | 0,05 ms | 415 ms | 0,03 ms |
| A3 | 503 / 21 | 55 ms | 0,30 ms | 611 ms | 13,0 ms |
| A4 | 503 / 21 | 55 ms | 0,30 ms | 519 ms | 13,4 ms |

Les latences des cinq bras sont descriptives. Le rejeu supervisé et une
partie des tests locaux ont partagé l’hôte pendant cette campagne.
L’écart entre A3 et A4 ne mesure donc pas un gain de vitesse dû à la mémoire.

## Récupération au niveau passage

| Modèle | Recall@5 | Recall@10 | nDCG@10 |
| --- | ---: | ---: | ---: |
| Qwen3-Embedding 512 | 94,5 % | 99,1 % | 0,906 |
| EmbeddingGemma 768 | 98,2 % | 100 % | 0,949 |

Les deux modèles franchissent le seuil de Recall@5 sur les 109 cas avec
passage annoté. Ce résultat ne mesure pas la décision de rejeter une
recherche sur les six cas sans passage pertinent. Gemma est le meilleur
candidat de récupération sur ce corpus court. Son adoption reste
conditionnée par les conditions Gemma et par une ablation générative
indépendante. Le bras génératif n’a utilisé que Qwen3-Embedding 512.

Qwen3 4B et Qwen3-Embedding sont publiés sous Apache 2.0. EmbeddingGemma
relève des conditions Gemma. Les trois modèles locaux ont été utilisés avec
leurs digests existants. [Qwen3 4B](https://huggingface.co/Qwen/Qwen3-4B),
[Qwen3-Embedding 0.6B](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B),
[EmbeddingGemma](https://huggingface.co/google/embeddinggemma-300m),
[conditions Gemma](https://ai.google.dev/gemma/terms).

## Sélection extractive V2

Sur les mêmes 115 cas, le sélecteur a rendu au moins un passage attendu
sur 101 des 109 cas avec passage annoté. Le rapprochement strict trouve
103 passages annotés sur 471 références restituées. Le résultat inclut
les passages en conflit rendus automatiquement par V2. Les deux cas
ORCHID-41 restituent ainsi les deux références et une abstention totale.
Sur les six cas sans passage pertinent, trois réponses s'abstiennent
totalement et trois conservent des passages hors jugement. Aucun paquet
de sélection n'a été rejeté. Ces chiffres évaluent le choix de références,
car le contrat extractif ne prononce pas de verdict.

## Revue supervisée réelle

Les replays crAPI, DVWA et Juice Shop ont chacun atteint `ready` avec
et sans mémoire, sur la même archive et le même journal privé V2. Les
empreintes des archives, projections et mémoires n’ont pas changé. Aucun
nouveau scan ou appel aux cibles n’a été réalisé.

| Archive | Éléments mémoire admissibles | Ajouts mémoire après déduplication | Passages transmis / cités | Faits restitués | Incertitudes restituées |
| --- | ---: | ---: | ---: | ---: | ---: |
| crAPI | 16 | 0 | 6 / 0 | 8 | 8 |
| DVWA | 16 | 0 | 6 / 0 | 8 | 7 |
| Juice Shop | 16 | 0 | 6 / 0 | 8 | 8 |

Les affirmations et leurs références sont identiques avec et sans mémoire
pour chaque archive. Les 16 observations sont déjà présentes avant le
budget final dans chaque revue. Le plafond amont de mémoire a écarté
respectivement 61, 64 et 78 groupes, qui ne font pas partie de cette
mesure. Les trois restitutions sont partielles. Les six
passages documentaires étaient accessibles au sélecteur sur chaque essai.
Leur absence dans les réponses montre que le classement documentaire
ne produit pas automatiquement une contribution au résumé de preuves.
Les validations pré et post-inférence ont pris 1,48 à 5,14 s sur ces
archives, contre 48 à 67 ms de récupération documentaire.

## Résidence des modèles

| Profil | Premier appel | Médiane des deux suivants | Pic VRAM | Marge VRAM | Pic RAM PSS Ollama |
| --- | ---: | ---: | ---: | ---: | ---: |
| Séquentiel | 28,50 s | 12,86 s | 4 298 Mio | 3 890 Mio | 3 042 Mio |
| Embeddings CPU et génération GPU | 14,26 s | 1,19 s | 4 231 Mio | 3 957 Mio | 2 315 Mio |
| Résidence simultanée GPU | 9,82 s | 0,87 s | 5 516 Mio | 2 672 Mio | 3 502 Mio |

Les trois profils franchissent la marge de 1 024 Mio sur la RTX 4060
Laptop de 8 188 Mio. En séquentiel, les deux requêtes suivantes rechargent
également les modèles. Le contrôle de résidence voit les embeddings
déchargés avant génération en séquentiel, présents sans VRAM sur le CPU
et présents sur GPU en simultané. Le modèle a consommé 468 tokens
d’entrée et 18 en sortie sur chacun des neuf appels. Les deux runtimes sont
arrêtés à la fin de l’essai. Le GPU revient à 0 Mio et les huit manifestes
de modèles ont conservé leurs empreintes.

Le profil **embeddings CPU et génération GPU** est recommandé comme
compromis de pilote sur l’hôte de travail. Il conserve 1 285 Mio de marge
GPU supplémentaire pour environ 320 ms de plus sur les deux appels
résidents mesurés. La résidence simultanée est le profil le plus rapide
sur un GPU dédié avec une marge contrôlée. Le séquentiel sert de référence
à faible résidence. Ces essais courts ne qualifient ni la concurrence,
ni des fenêtres plus longues, ni l’utilisation de plusieurs générateurs.

## Décision et priorités

Le banc montre un gain documentaire sur les verdicts de ce jeu. Le seuil
global du pilote génératif n’est pas franchi. Le parcours extractif et
supervisé reste la référence d’usage. Qwen3 4B reste la baseline du banc,
et aucune variante générative n’est promue. Qwen3-Embedding 512 reste la
configuration reproductible du parcours actuel. EmbeddingGemma 768 mérite
une comparaison de bout en bout avant toute substitution.

1. Faire dépendre le verdict local de la présence d’un appui admissible.
   Mesurer séparément l’abstention sur absence de réponse et la perte de
   cas répondables. L’augmentation du rappel seule ne traite pas cet échec.
2. Conserver les deux sources quand un conflit reste ouvert et vérifier
   que la synthèse ne transforme pas une incertitude en verdict définitif.
   Évaluer aussi la négation française et les citations qui réfutent le
   verdict rendu.
3. Étendre le jeu avec plusieurs passages par document, des sources proches
   en concurrence et des jugements de support indépendants. Compléter
   les canaris par des cas qui testent l’effet d’une instruction sur le
   verdict, même quand le schéma interdit de la recopier.
4. Mesurer l’apport de notes documentaires pertinentes dans une revue
   d’archive orientée vers une question de remédiation. Qualifier la
   mémoire uniquement avec des éléments admissibles qui survivent
   effectivement à la déduplication.

Les suites Python 3.14.6 et 3.12.15 ont chacune réussi 1 413 tests, avec 121
ignorés. Ruff, le formatage, Pyright et `git diff --check` ont réussi. Les
tests d’isolation système optionnels restent ceux de la qualification
du runtime. Les résultats de ce banc concernent la consultation hors ligne.
