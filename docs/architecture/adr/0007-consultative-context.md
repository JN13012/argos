# ADR 0007 — Contexte et restitution consultatifs V2

Statut accepté pour le pilote M3.5.5.

Le module transverse `argos.backend.consultation` définit les budgets, la
construction du contexte et la sélection de références. Les adaptateurs de
revue web résolvent un snapshot vérifié, interrogent la mémoire de la mission
et délèguent la recherche et les citations aux collections autorisées.
D’autres spécialisations peuvent fournir leurs propres unités et résolveurs.
Les observations de mission et les passages documentaires ont des relations
distinctes dans la réponse. Aucune interface d’exécution n’entre dans le
contrat du sélecteur.

Le pilote combine une borne avant envoi et des compteurs rapportés par le
runtime. Le tokenizer Qwen3 n’est pas dupliqué dans une nouvelle dépendance.
La borne en octets est conservatrice pour le format Qwen3 retenu et peut
laisser de la place inutilisée. Un autre fournisseur peut annoncer un
comptage compatible par le même contrat. Le modèle sélectionne des identifiants
et le programme restitue les éléments vérifiés. Cette approche limite les
affirmations générées et la surface d’injection, avec un coût en capacité
de synthèse et sans garantie de pertinence des sélections.

Le journal V1 conserve ses transitions. Les tentatives V2 ajoutent un contrat
et des empreintes, dont les éditions documentaires et la tête mémoire.
Les extraits restent transitoires pour réduire la duplication de données
privées. Les contrôles à la restitution et à l’acceptation privilégient
le refus en cas de changement concurrent, même si la modification concernait
un document différent. Les validations entre SQLite indépendants ne sont
pas atomiques.

Le CLI demande une durée de résidence nulle aux deux runtimes. L’essai
local a comparé la résidence CPU/GPU et GPU/GPU, avec suffisamment de mémoire
sur l’hôte mesuré. Les acquisitions de ressources de deux processus Argos
ou de clients tiers restent indépendantes. Les limites et les résultats
du pilote figurent dans la [spécification canonique](../../product/KNOWLEDGE_ENGINE_SPEC.md#f--m355--contexte-et-analyste-consultatifs-v2).

## Appui explicite à partir de M3.5.6.1

La restitution V2 associe un statut épistémique et un périmètre d’appui aux
éléments transmis. Un résolveur vérifie la source, les droits et le texte
exact. Le modèle sélectionne des références. L’attribution textuelle suit
un contrôle déterministe, tandis que l’implication sémantique pour une
question ouverte reste indéterminée. Le coût est mesuré sur le
[jeu de stress M3.5.6.1](../../product/M3561_RAG_RELIABILITY.md).

Depuis M3.5.6.2, l’attribution et le statut d’un reçu identifié se vérifient
par proposition. Les passages contestés et les valeurs contradictoires
conservent leurs références. L’analyse des résultats et le coût comparé
des options sémantiques figurent dans le
[bilan M3.5.6.2](../../product/M3562_PROPOSITION_VALIDATION.md).
