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
