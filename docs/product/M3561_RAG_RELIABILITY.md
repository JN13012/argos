# M3.5.6.1 — Appui des affirmations et fiabilité du RAG

Le contrat V2 améliore la distinction entre preuve, extrait et réponse au
niveau de l’objectif. Le pilote génératif reste non accepté. La restitution
extractive reste disponible pour la revue, avec l’état d’appui explicite.

## Audit du jeu historique

L’audit relit les 115 sorties brutes A4 de [M3.5.6](M356_RAG_EVALUATION.md),
les classements Qwen3 à dix passages, les passages transmis et les annotations.
Les catégories se recouvrent et indiquent le premier point où un manque
observable apparaît. Elles ne constituent pas une analyse interne du modèle.

| Écart observé | Cas | Étape |
| --- | ---: | --- |
| Passage attendu absent du top 10 | 1 | Récupération |
| Passage attendu classé mais absent du contexte transmis | 4 | Sélection du contexte, dont le plafond à six passages |
| Verdict erroné malgré les passages attendus transmis ou le reçu synthétique disponible | 15 | Interprétation et génération |
| Au moins une citation hors des passages annotés | 18 | Sélection du modèle et limite du contrôle de pertinence |
| Affirmation incorrecte ou sans citation d’appui selon le juge historique | 35 | Génération et absence de validation de l’appui du verdict |
| Rendu affirmatif ou négatif là où il fallait s’abstenir | 8 | Génération et absence de règle bloquante |
| Conflit déclaré ignoré malgré transmission des deux passages | 2 | Génération et absence de règle bloquante |
| Erreur sur un cas avec injection | 1 | ROTOR-7. Le verdict est erroné malgré une référence valide. Le marqueur ne sort pas du schéma. Attribution causale à l’injection indéterminée |

Le validateur historique vérifiait la résolution des citations et leurs droits.
Le banc de verdicts binaires n’exigeait pas de démonstration logique du lien
entre le verdict et l’extrait. Sur A4, aucun identifiant brut hors contexte ne
suffit à expliquer les 35 affirmations non appuyées. Dans les bras sans
documentation, les sorties ont parfois proposé des identifiants inexistants
que le rendu a exclus.

## Contrat et limites

Les relations V2 et la forme du journal restent lisibles. Les lignes portent
un `status` et un `support_scope`. La réponse et les nouvelles tentatives
portent l’identité `extractive-grounding-v1`.

- `verified_fact` délimite le fait à l’observation conservée dans l’archive
  vérifiée. Une réponse HTTP archivée ne prouve ni l’identité du compte ni
  l’état actuel du service.
- `supported_documentary_statement` attribue verbatim à la source le texte
  effectivement transmis, avec provenance, version et périmètre vérifiés.
  Le statut s’applique à l’attribution. Le contenu reste une donnée de la
  source.
- `inference` et `hypothesis` préservent une qualification explicitement
  transmise par le contexte. L’adaptateur de revue ne crée pas de nouvelle
  hypothèse à partir des documents.
- `contradiction` et `unknown` conservent les conflits déclarés et les
  incertitudes, indépendamment de la sélection. Le champ
  `grounding.objective_status` distingue l’appui à l’objectif du statut
  individuel des extraits. Le contrat restitue les éléments disponibles en
  abstention partielle et signale l’abstention totale si aucun appui de la
  catégorie requise n’a été retenu.

Une demande structurée `citation exacte: <texte>` vérifie l’occurrence d’un
passage complet, sans génération, à l’intérieur de la sélection accessible.
L’égalité distingue la casse, la ponctuation et les passages tronqués.
L’absence de résultat ne démontre pas l’absence dans le corpus. Les conflits
et limites reçus peuvent maintenir l’objectif indéterminé. Pour les demandes
ordinaires, le modèle sélectionne des références et le validateur s’abstient
de conclure sur l’objectif. La qualification de l’implication sémantique est
ouverte. Aucun modèle de validation sémantique n’a été utilisé.

## Qualification finale appariée

Les seuils M3.5.6 sont repris intégralement. Les entrées et critères ont été
figés dans `03e4d4c` avant les résultats du jeu final. Le développement utilise
quatre nouveaux cas et les huit cas de développement M3.5.6. Le nouveau final
contient 20 cas synthétiques français et anglais et 14 notes originales. Les
thèmes couvrent archives, remédiation, obsolescence, contradiction, citations
littérales, informations absentes et injections. Les annotations proviennent
du même assistant que les cas et n’ont pas reçu de validation humaine
indépendante. Prévoir une revue à l’aveugle des cas critiques et d’un
échantillon stratifié du reste par un second annotateur avant un feu vert.

Les classements par passage sont calculés à partir des collections réellement
indexées et des deux fournisseurs Ollama. Le mode avant émet un verdict
binaire avec abstention et références optionnelles. Le mode après appelle
l’analyste extractif V2 sur le même classement et marque comme indéterminé
tout objectif sans verdict démontré. Une occurrence littérale établie compte
comme oui. Les extraits d’une réponse partielle sont jugés également. Les
cas sont appariés mais les deux modes produisent des objets de nature
différente. Le résultat d’exactitude ne mesure pas l’utilité de lecture des
extraits. Toutes les mesures finales utilisent Qwen3 4B.

| Mesure | LLM seul | Qwen3 512 avant → après | EmbeddingGemma 768 avant → après |
| --- | ---: | ---: | ---: |
| Verdicts exacts | 7/20 | 13/20 → 7/20 | 13/20 → 7/20 |
| Affirmations non appuyées / verdicts affirmés | 3/3 | 7/19 → 0/0 | 7/19 → 0/0 |
| Précision des citations | 0 % | 85,0 % → 30,4 % | 76,2 % → 28,8 % |
| Rappel des citations | 0 % | 100 % → 100 % | 100 % → 100 % |
| Abstentions correctes | 6/7 | 1/7 → 7/7 | 1/7 → 7/7 |
| Abstentions sur cas répondables | 11/13 | 0/13 → 13/13 | 0/13 → 13/13 |
| Conflits conservés avec les deux références et abstention | 0/1 | 0/1 → 1/1 | 0/1 → 1/1 |
| Verdicts exacts sur cas avec injection | 0/2 | 2/2 → 0/2 | 2/2 → 0/2 |
| Observations d’archive critiques sélectionnées | 0/2 | 2/2 → 2/2 | 2/2 → 2/2 |
| Couverture critique avec verdict exact | 0/11 | 9/11 → 1/11 | 9/11 → 1/11 |

`0/0` laisse le taux d’affirmations non appuyées indéfini et la porte
correspondante échoue. Après modification, les deux profils rendent au
moins un passage attendu dans les 14 cas qui en annotent un, ainsi que
17 réponses partielles. Trois citations textuelles exactes ont été trouvées
et restituées mais des conflits d’un autre sujet dans les résultats de
récupération empêchent leur validation comme réponse à l’objectif. Les
preuves et conflits gagneraient à être reliés par proposition plutôt
qu’évalués au niveau de l’enveloppe entière.

Les deux modèles d’embeddings obtiennent 100 % de rappel aux rangs 5 et 10
et 0,974 de nDCG@10 sur 14 cas annotés. Ce petit ensemble de notes courtes
ne discrimine pas leur qualité. Le délai médian de recherche sur CPU a
été de 192 ms pour Qwen3 et 64 ms pour EmbeddingGemma sur cet essai.
La génération et la validation médianes sont de 587/11 ms avant et
539/23 ms après pour Qwen3, puis 597/12 ms avant et 603/27 ms après pour
EmbeddingGemma. L’assemblage médian reste sous 0,4 ms. Les tokens médians
entrée/sortie passent de 423/21 à 393/6 et de 421,5/21 à 387,5/8
respectivement. Les deux modes après culminent autour de 4 232 Mio de
VRAM totale échantillonnée. Les mesures incluent les conditions locales
de résidence et la sélection peut s’effectuer sans requête modèle dans
les cas littéraux.

Aucun marqueur d’injection ne sort comme verdict ou synthèse générée.
Les citations verbatim ont toutefois exposé des marqueurs dans cinq
réponses par embedding, y compris lorsque ces passages étaient des
distracteurs. Une citation doit rester traitée comme donnée si un client
la réinjecte dans un autre contexte. Ces mesures établissent une contrainte
sur la sortie contrôlée et la conservation des données citées. La robustesse
sémantique de l’analyse est insuffisante. La preuve est particulièrement
limitée par un seul conflit annoté, deux injections et une forte proportion
de notes courtes avec identifiants explicites.

## Développement et choix provisoires

Les cinq modèles ont reçu les mêmes 12 questions et contextes, via leur
gabarit conversationnel natif, avec température 0, fenêtre 8 192 et
réserve 96. Le générateur est déchargé entre les séries. Les métriques
ci-dessous décrivent les propositions de verdict, avant la politique
extractive. L’exactitude de cette comparaison n’entre pas dans la porte du
jeu final. Tous les modèles ont produit des réponses analysables. Aucun
n’a présenté de marqueur en sortie.

| Modèle | Exactitude | Précision / rappel citations | Affirmations non appuyées | Abstentions correctes | Tokens méd. entrée / sortie | Génération méd. | Pic VRAM / PSS Ollama |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3 4B | 5/12 | 90,9 / 100 % | 58,3 % | 0/2 | 367 / 10 | 456 ms | 4 225 / 3 980 Mio |
| Qwen3 8B | 10/12 | 83,3 / 100 % | 16,7 % | 0/2 | 373 / 10 | 621 ms | 6 239 / 2 846 Mio |
| DeepSeek-R1 7B | 5/12 | 76,9 / 100 % | 58,3 % | 0/2 | 359 / 10 | 466 ms | 5 249 / 2 388 Mio |
| Gemma 3 4B | 10/12 | 52,9 / 90 % | 27,3 % | 1/2 | 365 / 10 | 558 ms | 6 051 / 4 223 Mio |
| Qwen2.5 0.5B | 5/12 | 23,8 / 100 % | 58,3 % | 0/2 | 365 / 14 | 281 ms | 903 / 2 451 Mio |

Le pic VRAM est celui de la carte entière, relevé par NVML. Le PSS regroupe
les processus des deux services Ollama et inclut le chargement. Ce total
n’est pas une mesure de toute la RAM système. Les valeurs sont des maxima
échantillonnés et peuvent manquer les transitoires. Les traces initiales
dans `development/` conservent une première exécution avec transitions
de résidence entre modèles. Les mesures de la table proviennent de
`development-isolated/`. Les deux séries donnent les mêmes verdicts
corrects par modèle en nombre.

Conserver Qwen3 4B comme référence. Qwen3 8B est le prochain candidat
génératif à qualifier au vu de l’exactitude et de l’appui sur développement,
avec un pic VRAM plus élevé et aucune abstention correcte ici. Conserver
Qwen3-Embedding 512 comme référence opérationnelle. Tester EmbeddingGemma 768
sur des passages plus longs et un corpus diversifié sous les conditions
Gemma. Son délai CPU inférieur dans cette série mérite une réplication.
Le profil embeddings CPU et génération GPU reste le profil de référence
de [M3.5.6](M356_RAG_EVALUATION.md). Les profils matériels concurrents
n’ont pas été remesurés dans ce lot.

Priorités avant qualification du pilote :

1. Relier l’appui, la contradiction et l’incertitude à chaque proposition
   plutôt qu’au contexte entier. Couvrir les cas de citation exacte en
   présence d’une contradiction hors sujet.
2. Qualifier un filtrage des passages réellement utiles et limiter les
   citations attribuées qui contiennent des consignes. Conserver leur
   provenance et mesurer les pertes de rappel.
3. Évaluer la validation sémantique dans un bras distinct si elle devient
   nécessaire. Comparer à des jugements humains sur le lien entre chaque
   affirmation, son appui et son état de confiance.
4. Refaire une comparaison appariée sur un nouveau jeu plus diversifié
   avec annotations revues à l’aveugle. Mesurer les réponses récupérées
   par rapport au taux d’erreurs et d’abstentions.

## Mémoire

Les résultats privés de M3.5.6 donnent, pour crAPI, DVWA et Juice Shop,
16 observations mémoire admissibles sur 16 déjà présentes avant application
du budget. La fonction de capture dérive ses observations du même snapshot.
Le contexte courant vérifie le même UID, la mission, le snapshot de travail et
l’origine `verified_archive`, puis vérifie l’identité canonique avec les
observations de l’archive. L’assembleur donne priorité à la copie archive en
dédupliquant leur identité commune. Il resterait possible que la mémoire
réintroduise une observation omise par la projection de l’archive, dans les
limites des budgets. Les 61, 64 et 78 groupes omis en amont ne renseignent pas
sur ce cas. Les annotations, anciennes conclusions du modèle et observations
d’un autre snapshot n’acquièrent aucun statut probant. Le contrat mémoire
reste identique.

## Reproduction

Exécuter depuis le dépôt sur les runtimes locaux existants. Chaque répertoire
de sortie d’essai doit être nouveau. Le banc enregistre sorties, indices,
empreintes, durées, comptes de tokens, PSS des groupes Ollama et VRAM totale
échantillonnée. Les répertoires de qualification sont exclus de Git.

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
OUT=data/qualification/m3561
mkdir -p "$OUT"
python -m benchmarks.rag_reliability.audit data/qualification/m356/final \
  --out "$OUT/historical-audit.json"
python -m benchmarks.rag_reliability.run --split development --out "$OUT/development-isolated"
python -m benchmarks.rag_reliability.run --split final --out "$OUT/final"
python -m benchmarks.rag_reliability.report "$OUT/final" > "$OUT/final/report.json"
```

Les essais utilisent la variante EmbeddingGemma 300M installée et Gemma 3
4B selon les conditions Gemma. Les fixtures sont synthétiques et les
modèles restent locaux. [Conditions Gemma](https://ai.google.dev/gemma/terms).

La commande produit utilise les collections Argos publiées. Le mode lexical
permet de demander une citation déterministe lorsqu’aucun index vectoriel
n’est disponible. Le fournisseur et l’identification du modèle restent
configurés par les options de revue V2.

```bash
python -m argos review documentary-v2 --collection user --mode lexical \
  --objective 'citation exacte: Texte complet du passage publié.'
```

La qualification de non-régression utilise les suites régulières sous
Python 3.12 et 3.14, avec Ruff, le contrôle de formatage, Pyright sur le
produit et le banc, puis `git diff --check`. Les journaux pytest sont
conservés dans le répertoire local de qualification. Les empreintes des
huit manifestes Ollama correspondent à l’inventaire antérieur. Les deux
runtimes utilisés sont Ollama 0.11.11 et 0.40.18.
