# M3.5.6.2 — Raisonnement et validation par proposition

## Diagnostic des 13 abstentions

Le [bilan M3.5.6.1](M3561_RAG_RELIABILITY.md) fournit les réponses, classements
et contextes utilisés. Chaque contrôle rejoue le prompt binaire historique
avec Qwen3 4B. Il utilise d’abord le paquet transmis, puis uniquement les
passages annotés et, lorsqu’il existe, le reçu synthétique vérifié. Le contexte
de référence vient du paquet réel. Aucun passage extérieur n’a dû être ajouté.

| Composant | Constat sur les 13 cas |
| --- | --- |
| Récupération | Les 13 appuis attendus étaient déjà disponibles dans le classement et dans le contexte. |
| Assemblage du contexte | Le contexte réel conservait les éléments attendus, dont les reçus synthétiques. Huit paquets contenaient aussi une contradiction hors sujet. |
| Prompt extractif | Le sélecteur historique produisait des identifiants, avec au moins une référence attendue dans les 13 cas. Il ne produisait aucun verdict. |
| Modèle génératif | Le rejeu binaire obtient 11/13 avec chacun des contextes. `r03` et `r05` sont erronés dans les deux contrôles. `r05` était correct dans la trace historique initiale. Le contrôle ne permet pas d’attribuer cette variation à l’injection. |
| Contrat et validateur | La validation prouvait la résolution et l’attribution des extraits. Les dix questions ordinaires n’avaient pas de champ de verdict appuyé. |
| Abstention | Le veto global bloquait les trois citations littérales exactes `r07`, `r08`, `r14`. Le motif d’implication non vérifiée s’appliquait aux dix autres. |

Cette attribution sépare la perte de verdict fonctionnelle des deux erreurs
réelles d’interprétation. Le routeur, le classement vectoriel et les budgets
d’assemblage conservent le comportement de M3.5.6.1. Les contrôles du modèle
sur le contexte de référence ne démontrent pas une compréhension générale.

## Contrat consultatif

La politique `extractive-grounding-v2` conserve la réponse V2, la sélection
par identifiants et les statuts des observations, inférences et hypothèses.
Les demandes typées ajoutent un tableau `propositions` à la réponse.

- `Attribution(text)` vérifie un passage documentaire complet transmis et
  admissible. La comparaison préserve la casse et la ponctuation. Une
  contradiction d’un autre sujet reste citée dans la réponse et ne bloque
  plus l’attribution. Un passage exact marqué contesté garde l’état
  `undetermined` avec sa référence.
- `RecordedHTTPStatus(receipt_id, status)` compare le statut numérique avec
  l’observation liée au reçu HTTP du snapshot vérifié. Un autre statut sur
  ce reçu contredit la proposition. Le document qui contient le même texte
  reste une source documentaire. Un reçu absent laisse l’appui insuffisant.
  Un désaccord entre observations du même reçu garde les deux références.
- Une proposition obtient un des états `supported`, `contradicted`,
  `insufficient` ou `undetermined`. Les résultats sont indépendants. Les
  états résolus restent disponibles à côté des états ouverts. Chaque appui
  porte son propre périmètre et ses références.
- Le demandeur peut fournir jusqu’à huit propositions typées aux fonctions
  de revue V2. La demande existante `citation exacte: …` utilise
  automatiquement une proposition. La tentative supervisée épingle
  l’empreinte des propositions explicitement fournies. Les contrôles
  existants avant et après le traitement restent applicables.
- La restitution des questions libres reste extractive. Les modèles
  sémantiques expérimentaux n’entrent ni dans la décision produit ni
  dans les autorisations. Le code de vérification n’accède à aucun outil.

L’attribution textuelle établit la présence d’une phrase dans un passage.
La comparaison d’un reçu porte sur un champ structuré. La vérification
sémantique des inférences reste distincte et expérimentale.

## Protocole

Le commit `130d4cb` fige huit cas de développement et seize cas finaux
différents, leurs passages, les prompts, la matrice des essais et les
seuils historiques. Les cas sont des fixtures bilingues produites par un
seul annotateur assistant. Aucune validation humaine indépendante n’a
été réalisée. Chaque cas est jugé au niveau du passage ou du reçu
synthétique. Le jeu final M3.5.6.1 sert exclusivement au diagnostic.

Une collection SQLite isolée est construite pour chaque jeu. Le même
classement de l’index Qwen3-Embedding 512 est utilisé par les deux
générateurs. La fenêtre de 8 192 tokens et la réserve de 96 sont identiques.
Le protocole compare le LLM seul, le verdict génératif historique, V2
extractif avec l’ancienne règle, V2 par proposition et un verdict
sémantique expérimental. La seconde passe par le même modèle reçoit la
proposition et les passages originaux sur le développement uniquement.
Elle est comptée séparément. La simulation de l’ancien V2 reprend sa
sélection et réapplique sa règle d’abstention globale à la citation exacte.

## Développement

| Configuration | Qwen3 4B | Qwen3 8B |
| --- | ---: | ---: |
| LLM seul | 5/8 | 2/8 |
| Verdict historique avec contexte | 7/8 | 5/8 |
| Extractif M3.5.6.1 | 3/8 | 3/8 |
| Propositions déterministes | 6/8 | 6/8 |
| Sémantique en une passe | 6/8 | 6/8 |
| Sémantique avec seconde vérification | 5/8 | 4/8 |

La seconde passe retranche un verdict exact au 4B et deux au 8B. Elle
ajoute respectivement 696 et 741 ms en médiane hors première génération.
Sur le 8B, elle ne conserve plus complètement la contradiction qu’avait
rendue la première passe. Elle n’est pas retenue. La validation
sémantique à une passe reste un bras de comparaison.

## Jeu final

La couverture mesure la part des 11 questions répondables auxquelles
le bras attribue un verdict. L’exactitude conditionnelle dans ce groupe
ne pénalise pas une affirmation portée à tort sur un des cinq cas
indéterminés. Le taux d’affirmations non appuyées porte sur tous les
verdicts affirmés et complète cette mesure. Le juge combine exactitude
du verdict et correspondance avec les références annotées.

| Générateur et configuration | Exactitude | Couverture | Exactitude parmi les cas répondables traités | Abstentions correctes | Abstentions injustifiées | Affirmations non appuyées | Précision / rappel citations | Conflits complets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4B seul | 7/16 | 3/11 | 3/3 | 4/5 | 8/11 | 4/4 | 0 / 0 % | 0/2 |
| 4B historique | 8/16 | 11/11 | 8/11 | 0/5 | 0/11 | 9/16 | 58,8 / 71,4 % | 0/2 |
| 4B extractif M3.5.6.1 | 5/16 | 0/11 | Indéfinie | 5/5 | 11/11 | 0/0 | 30,4 / 100 % | 2/2 |
| 4B déterministe | 10/16 | 5/11 | 5/5 | 5/5 | 6/11 | 0/5 | 43,8 / 100 % | 2/2 |
| 4B sémantique | 11/16 | 8/11 | 8/8 | 3/5 | 3/11 | 2/10 | 50,0 / 100 % | 1/2 |
| 8B seul | 6/16 | 9/11 | 5/9 | 1/5 | 2/11 | 13/13 | 0 / 0 % | 0/2 |
| 8B historique | 11/16 | 11/11 | 11/11 | 0/5 | 0/11 | 5/16 | 82,4 / 100 % | 0/2 |
| 8B extractif M3.5.6.1 | 5/16 | 0/11 | Indéfinie | 5/5 | 11/11 | 0/0 | 41,2 / 100 % | 2/2 |
| 8B déterministe | 10/16 | 5/11 | 5/5 | 5/5 | 6/11 | 0/5 | 53,8 / 100 % | 2/2 |
| 8B sémantique | 9/16 | 11/11 | 9/11 | 0/5 | 0/11 | 8/16 | 72,2 / 92,9 % | 0/2 |

`0/0` est un taux indéfini et échoue à la porte correspondante. La
validation déterministe récupère trois attributions littérales et deux
comparaisons de reçu, toutes exactes. Les six questions libres restantes
gardent une restitution extractive sans verdict. Aucun bras ne satisfait
tous les seuils historiques. Les deux bras déterministes échouent sur
l’exactitude absolue, la précision des citations et l’abstention injustifiée.

La retenue de références peut exposer des consignes dans les citations
documentaires. Aucun marqueur n’apparaît dans les verdicts ou synthèses
contrôlés. Les bras déterministes citent un marqueur dans trois réponses
avec le 4B et deux avec le 8B. Ils s’abstiennent sur les deux cas notés
d’injection, répondables. Le 4B sémantique répond correctement aux deux
cas, le 8B à un seul. Ce sous-ensemble est trop petit pour qualifier la
robustesse générale. Ses extraits restent des données non fiables.

### Performances observées

| Configuration | Tokens médians entrée / sortie | Génération méd. / p95 observé | Validation méd. |
| --- | ---: | ---: | ---: |
| 4B historique | 405,5 / 21 | 595 / 638 ms | 12 ms |
| 4B déterministe | 173,5 / 3 | 214 / 623 ms | 24 ms |
| 4B sémantique | 429,5 / 21 | 674 / 792 ms | 12 ms |
| 8B historique | 405,5 / 10 | 633 / 728 ms | 11 ms |
| 8B déterministe | 173,5 / 3 | 264 / 670 ms | 22 ms |
| 8B sémantique | 429,5 / 10 | 714 / 801 ms | 11 ms |

La génération du bras déterministe comprend des cas à zéro token, où le
programme vérifie directement la proposition, et les cas libres, où le
sélecteur tourne. La VRAM totale échantillonnée culmine à 4 231 Mio sur
le 4B et 6 245 Mio sur le 8B, avec des PSS Ollama respectifs de 2 867 et
5 497 Mio. La carte dispose de 8 188 Mio. Le classement documentaire CPU
partagé obtient 100 % de rappel aux rangs 5 et 10 et 0,966 de nDCG@10. La
recherche médiane de 2 178 ms comprend le redémarrage du modèle
d’embeddings entre requêtes dans cette configuration de banc. Sa phase
atteint 1 213 Mio de PSS Ollama et 0 Mio de VRAM. Ces pics échantillonnés
décrivent les processus Ollama et la carte entière. Les mesures p95 de
génération se limitent à seize cas par bras.

## Configuration stable et limites

Conserver Qwen3 4B, Qwen3-Embedding 512 et le V2 extractif avec validation
déterministe pour les demandes typées. Sur ces cas, le 8B ne gagne aucun
verdict déterministe, et son verdict sémantique est moins fiable. La
seconde vérification a dégradé les résultats de développement. Le pilote
génératif reste non qualifié.

L’étape suivante devra se concentrer sur la validation de propositions
sémantiques libres et sur le choix des citations pertinentes. Elle devra
mesurer l’appui, les erreurs et l’abstention sur un jeu apparié plus large
et revu indépendamment. Les deux essais de modèle restent des comparaisons
locales sur de courtes notes contenant des identifiants explicites.
La couverture des contradictions reste limitée à deux cas de conflit
et de passage contesté. Le cas de deux statuts incompatibles pour un même
reçu possède un test dédié. Le jeu final ne contient jamais plus d’un
statut par reçu.

## Reproduction

Chaque sortie d’essai est un nouveau répertoire local. Le banc enregistre
les passages et contextes, les identifiants bruts, les sorties des modèles,
les tokens, les empreintes, les durées et les échantillons matériels.

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
OUT=data/qualification/m3562
mkdir -p "$OUT"
python -m benchmarks.rag_propositions.diagnose data/qualification/m3561/final \
  --out "$OUT/diagnosis"
python -m benchmarks.rag_propositions.run --split development --out "$OUT/development"
python -m benchmarks.rag_propositions.run --split final --out "$OUT/final"
python -m benchmarks.rag_propositions.report "$OUT/development" > "$OUT/development/report.json"
python -m benchmarks.rag_propositions.report "$OUT/final" > "$OUT/final/report.json"
```

La commande V2 existante reste disponible pour vérifier l’attribution
complète d’un passage publié.

```bash
python -m argos review documentary-v2 --collection user --mode lexical \
  --objective 'citation exacte: Texte complet du passage publié.'
```

Le contrôle ciblé des statuts et références a rejoué les 24 propositions
typées conservées dans les traces sur le dernier code. Les résultats
concordent avec la série mesurée. Les journaux de non-régression Python
3.12 et 3.14 et les agrégats du banc restent dans le répertoire de
qualification local. Les deux runtimes Ollama et les huit manifestes
ont été vérifiés sans changement de modèle.
