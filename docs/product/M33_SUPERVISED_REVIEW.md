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
