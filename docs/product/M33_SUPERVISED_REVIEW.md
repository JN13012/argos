# M3.3 — Supervised Review Workflow

Le workflow coordonne la revue consultative de missions archivées. Il réutilise
le snapshot vérifié M3.1, son Evidence Engine, le contexte expurgé, l'analyste
M3.2 et le Decision Journal. Il ne sélectionne pas d'action offensive et
n'importe aucun mécanisme d'exécution ni d'autorisation de mission.

## Contrat et persistance

`workflow.py` expose `create_workflow`, `read_workflow`, `analyze_workflow`,
`annotate_workflow`, `interrupt_workflow` et `accept_workflow`. Chaque revue
possède un UUID ; son historique est versionné `supervised-review-v1`.
Les événements sont conservés dans le SQLite privé du journal opérateur, séparé
de la base de mission. L'[ADR 0003](../architecture/adr/0003-supervised-review-journal.md)
explique les transactions, empreintes et limites de reprise.

La création fige **un seul** snapshot vérifié, son contexte compact de 8 Kio,
les preuves et **tous** les éléments `contradiction` / `unknown` exposés par le
snapshot, avant la réduction du contexte ou la déduplication du modèle.
Ce volet critique persiste sur succès, erreur et interruption. Les limites
propres au snapshot (archives plafonnées, projections absentes) restent
visibles ; « complet » signifie ici complet dans cette vue, pas dans le monde
réel. Les autres faits et inférences restent consultables via le contexte
et la synthèse, avec leurs sources.

Le cycle est `created → analyzing → ready | failed | interrupted`, puis
`ready → accepted`. Une reprise explicite peut repartir de `failed`,
`interrupted` ou `ready` vers `analyzing` ; une revue acceptée reste terminale.
Une nouvelle revue est requise si le snapshot actuel diffère. Les preuves
sont revérifiées avant chaque inférence et acceptation. Le refus d'une archive
altérée ne lance pas de modèle et laisse l'état précédent intact.

Chaque tentative conserve le prompt exact expurgé, le schéma, leur empreinte,
le fournisseur, le nom configurable du modèle, port, timeout, options fixes
M3.2, réponse structurée du fournisseur, usage tokens, latences, résultat et
erreur bornée. La réponse stockée est la `LLMCompletion` du contrat fournisseur,
pas le corps HTTP brut Ollama ; ce dernier est conservé par le banc M3.2.1.
La configuration lie un nom/tag de modèle : elle ne certifie pas à elle seule
que des poids sous ce tag n'ont jamais changé. Les tables ne constituent pas
une signature cryptographique contre leur propriétaire.

Un état `analyzing` après arrêt brutal n'est jamais relancé implicitement.
Après vérification que le processus est mort, l'opérateur le marque interrompu
et relance une tentative. Cette opération ne tue pas un serveur Ollama vivant.
Les réponses tardives d'une tentative remplacée sont refusées par comparaison
de l'empreinte précédente. Les annotations attendent la fin d'une inférence.
Les erreurs inattendues du fournisseur sont tracées par un code sûr puis
remontées à l'appelant ; une reprise reste possible.

La validation exige une décision explicitement fournie par l'humain, avec
motivation, contexte et références vérifiées selon le contrat M3.1. Elle est
archivée par le Decision Journal, puis liée à l'analyse et à la revue.
`execution_authorized` reste toujours `false`. Ni les annotations ni les
conclusions du modèle ne deviennent des instructions exécutables.

## Utilisation CLI

```bash
# Journal créé en mode 600 ; archive source privée existante, jamais modifiée
.venv/bin/python -m argos review workflow-start \
  --db ARCHIVE.sqlite --mission-id UUID --journal JOURNAL.sqlite
# Conserver le review_id renvoyé
.venv/bin/python -m argos review workflow-show \
  --journal JOURNAL.sqlite --review-id REVIEW_UUID
# Démarrer séparément le serveur local, puis analyser explicitement
scripts/llm/ollama-local serve
.venv/bin/python -m argos review workflow-analyze \
  --db ARCHIVE.sqlite --journal JOURNAL.sqlite --review-id REVIEW_UUID --model qwen3:4b
# Note JSON privée : {"operator":"nom","note":"constat de revue"}
.venv/bin/python -m argos review workflow-annotate \
  --journal JOURNAL.sqlite --review-id REVIEW_UUID --input NOTE.json
# Après mort vérifiée du processus, même contrat JSON pour expliciter la reprise
.venv/bin/python -m argos review workflow-interrupt \
  --journal JOURNAL.sqlite --review-id REVIEW_UUID --input INTERRUPTION.json
# Puis workflow-analyze relance explicitement une nouvelle tentative
# Validation : contrat JSON du journal M3.1, jamais rédigé par le modèle
.venv/bin/python -m argos review workflow-accept \
  --db ARCHIVE.sqlite --journal JOURNAL.sqlite --review-id REVIEW_UUID --input DECISION.json
```

Les fichiers d'entrée doivent être privés (`chmod 600`). Le JSON de décision
contient `id` (UUID stable à réutiliser lors d'un retry), `snapshot_sha256`,
`sources` (`kind`, `id`), `operator`, `decision`, `rationale` et `context`.
La commande `review journal-show` permet de relire cette décision vérifiée.
Une seconde soumission identique après succès est idempotente.

`workflow-show --expected-head SHA256` compare un checkpoint global conservé
séparément. `--history` inclut explicitement le snapshot privé figé, les requêtes,
complétions et annotations. Sans ce drapeau, la sortie omet les événements et
le snapshot complet. Ne pas publier cet historique ni les journaux privés.
Les commandes d'analyse ne démarrent pas de serveur et ne téléchargent rien.
Le modèle reste librement configurable ; l'alternative légère est `qwen2.5:0.5b`.
