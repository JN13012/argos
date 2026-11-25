# M3.2.1 — Benchmark local des synthèses consultatives

Le banc `benchmarks/llm/benchmark.py` est un outil de développement distinct
de l'analyste produit. Il réutilise le prompt, le schéma et le validateur M3.2.
Les trois contextes M2.7.1 sont figés avant les appels aux modèles et restent
privés. Deux fixtures indépendantes couvrent une réponse HTTP, une inférence,
un conflit et une inconnue d'authentification parmi dix observations secondaires.
La deuxième inverse leur ordre. Les références attendues restent exclusivement
chez l'évaluateur.

Le banc décharge chaque modèle avant chaque cas, puis mesure une réponse froide
et deux réponses chaudes. Les tokens/s utilisent `eval_count / eval_duration`
rapportés par Ollama. La latence inclut le POST et sa réponse. La RAM est le
maximum des RSS des processus Ollama, échantillonné toutes les 100 ms. Des pages
partagées peuvent être comptées deux fois. La VRAM résidente vient de `/api/ps`.
Ces mesures ne constituent pas une mesure de pic VRAM durant le préremplissage.

La validité JSON et la fidélité des références sont contrôlées avant la note.
La précision de pertinence compte les références importantes sélectionnées sur
l'ensemble de la sélection. Le rappel compte les informations importantes
retenues parmi les quatre attendues. Les archives réelles sont sans oracle
sémantique expert et restent explicitement non notées. Une sélection valide
sur une archive n'obtient aucune note implicite de pertinence.

```bash
PYTHONPATH=. python benchmarks/llm/benchmark.py --port 11534 \
  --cases CONTEXTES_PRIVES.json --output RESULTATS_PRIVES.jsonl
python -m pytest -q tests/test_local_llm_benchmark.py
```

Les fichiers de contexte contiennent une liste d'objets avec `name`, `context`
et `required` (vide pour les archives sans oracle). Les sorties détaillées,
modèles et contextes restent hors Git. Le banc ne modifie aucune mission.

## Qualification du 25 novembre 2026

M3.2 a été relu et intégré en fast-forward à `main`, SHA `9b000a3`.
Les 1 229 tests réguliers passent, avec 121 ignorés. Ruff et Pyright passent.
Les trois jobs de la [CI du SHA publié](https://github.com/JN13012/argos/actions/runs/45670050050)
sont réussis. M3.2.1 demeure sur sa branche de validation.

WSL expose `/dev/dxg` et une RTX 4060 Laptop GPU, 8 188 Mio. La machine
présente 16 processeurs logiques et 15 Gio de RAM. Ollama Linux 0.11.11,
paquet officiel vérifié par SHA-256, détecte CUDA compute 8.9. Les journaux
confirment le transfert de couches sur GPU, dont 25/25 pour la baseline et
37/37 pour Qwen3 4B. Certains chargements restent partiels (36/37 couches).
Le moniteur NVIDIA observe jusqu'à 6 258 Mio et 100 % d'activité GPU pendant
la campagne. Les tailles `/api/ps` ci-dessous utilisent la comptabilité
résidente Ollama et peuvent différer du relevé NVIDIA. La détection d'un GPU
est ainsi corroborée par les transferts, la résidence et l'activité observée.

Les cinq modèles sont des GGUF Q4_K_M. Leurs manifestes exacts et les
agrégats sont conservés dans [results.json](../../benchmarks/llm/results.json).
Les poids et bibliothèques restent dans le répertoire privé ignoré. Les
licences des couches téléchargées indiquent Apache 2.0 pour Qwen2.5/Qwen3,
les conditions Gemma pour Gemma 3, et MIT pour DeepSeek-R1 Distill Qwen.
Ils utilisent le même client HTTP, une température nulle, 8 192 tokens de
contexte, 384 de sortie au plus et `think=false`, conformément à M3.2.
La qualification a lieu dans un espace réseau limité à loopback. Aucun
modèle ne dispose d'outil, de terminal ou d'autorisation de mission.

| Modèle | Valides | Froid moyen s | Chaud moyen s | Tokens/s moyens | RSS max Gio | VRAM résidente max Gio | Précision fixture | Rappel fixture |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen2.5 0.5B | 15/15 | 5,01 | 0,56 | 91,7 | 1,38 | 1,21 | 6,25 % | 12,5 % |
| Qwen3 4B | 15/15 | 8,01 | 0,92 | 52,3 | 3,26 | 4,73 | 26,8 % | 50 % |
| Gemma 3 4B | 15/15 | 9,45 | 0,86 | 44,0 | 3,43 | 4,45 | 6,25 % | 12,5 % |
| Qwen3 8B | 15/15 | 11,74 | 0,95 | 27,2 | 2,28 | 6,53 | 6,25 % | 12,5 % |
| DeepSeek-R1 Distill Qwen 7B | 15/15 | 9,86 | 1,19 | 39,5 | 5,52 | 5,58 | 6,25 % | 12,5 % |

Chaque cas conserve les mêmes références dans les trois répétitions pour
chaque modèle. Les 75 réponses satisfont les contraintes de références.
Leurs valeurs et états sont restitués depuis le contexte, ce qui garantit
leur liaison aux preuves de M3.1. Cette propriété ne mesure pas une capacité
de raisonnement libre ou une fidélité de prose générée.

La qualité sémantique reste insuffisante sur ce petit corpus. Aucun des cinq
modèles ne sélectionne la contradiction et l'inconnue importantes des fixtures,
sur les six passages évalués par modèle. Les synthèses finales d'Argos
ajoutent des représentants déterministes pour les catégories omises, mais
ces compléments sont exclus des scores du modèle. Qwen3 4B retient davantage
de contenu pertinent, sans résoudre les omissions critiques. La sensibilité
à l'ordre reste visible dans les résultats de la baseline. Les archives
réelles n'ont pas fait l'objet d'une notation experte indépendante.

## Recommandation et limites

Qwen3 4B Q4_K_M est le choix par défaut recommandé pour poursuivre la revue
consultative sur cette RTX 4060. Il a le meilleur rappel mesuré et conserve
une marge de VRAM. Qwen2.5 0.5B Q4_K_M est l'alternative légère pour les
contraintes mémoire et de délai, avec sa baisse de pertinence explicitée.
La commande produit garde le choix explicite `--model`. Cette recommandation
porte sur la configuration testée et ne vaut pas qualification d'une analyse
fiable des contradictions. Le raisonnement des modèles de type R1 avec une
sortie de réflexion étendue n'a pas été évalué.

Le froid correspond au modèle déchargé de la VRAM, avec les poids déjà sur
disque et le cache système potentiellement chaud. Le faible nombre de cas,
les réponses très courtes, les caches de prompt, l'absence d'oracle expert
sur les archives et la grammaire des sorties limitent la généralisation.
La stabilité observée concerne trois réponses par cas et température zéro.
Le RSS et la VRAM sont mesurés par deux sources différentes. La campagne
n'évalue ni les pics précis de mémoire CUDA ni une concurrence multi-mission.
M3.3 reste à faire.

## Validation de la tranche

Les deux tests de score et de séparation des réponses attendues passent sous
Python 3.12 et 3.14. La suite régulière finale compte 1 231 réussites et
121 tests ignorés sous chacun des deux interpréteurs. Ruff, le formatage,
Pyright, les liens locaux, le JSON des agrégats et `git diff --check` passent.
Les essais hôte de reconnaissance optionnels restent désactivés.
