# M3.5.9 — Qualification du workflow intégré

Base d’audit `74b3221f8120a6cd0d3365eff2a13b2a35d74280`. Cette tranche
évalue le workflow de restitution et de revue existant sur archives et
fixtures locales bénignes. Les procédures réseau, capacités et autorisations
de mission restent celles du produit au SHA de base.

## Audit stratégique post-M3.5

Le CLI orchestre une reconnaissance déterministe en environnement qualifié,
des requêtes HTTP bornées et un navigateur supervisé. La matrice W6 observe
WEB-01 et WEB-02 et rapporte le contrôle ciblé WEB-04. Les 17 autres familles
sont non testées dans cette matrice. W4.3c demeure la dépendance des formulaires
et sessions. W7 et la reprise d’un plan autonome complet sont des objectifs
d’architecture. W8 dispose d’un évaluateur partiel et W9 reste conditionné aux
preuves de couverture et d’exploitation.

M2.7.1 couvre 7/11 ressources échantillonnées sur Juice Shop 19, 5/11 sur
crAPI v1 et 5/11 sur DVWA pour la configuration contextuelle. L’identification
passe de 2/7 à 6/7 technologies avec le même rappel de l’échantillon et 133
tickets contre 76. Le refus initial crAPI reste au bilan avant son essai
indépendant réussi. M2.0.1 utilise une autre image Juice Shop, avec 5/37 GET
du référentiel, deux changements d’états de défi et zéro constat Argos
confirmé. Ces trois mesures ont chacune leur dénominateur.

M3.1–M3.4 relient preuves, snapshot, journal, revue et mémoire sur ces archives.
M3.5.8 est intégré à main avec une qualification locale de la restitution
extractive et des projections documentaires. Le pilote génératif reste non
qualifié. Le RAG a fait progresser le verdict du banc M3.5.6 de 47,8 % à
81,7 % d’exactitude, avec des seuils absolus manqués et sans annotation humaine
indépendante. M3.5.6.2 traite correctement cinq des onze cas répondables avec
les propositions typées. Le CLI d’archive transmet un objectif sans ces
propositions. L’effet propre de la mémoire reste à établir. Les trois replays
M3.5.6 n’ajoutent aucune unité après déduplication.

State, Evidence, Memory et Knowledge ont des magasins distincts. V2 vérifie
leurs points de contrôle et transmet au modèle une projection bornée. Lors
d’une revue d’archive, la recherche documentaire dérive des statuts HTTP et
technologies du snapshot. La pertinence par rapport à l’objectif, le coût de
validation en volume et l’utilité de la sélection doivent être mesurés. La
réponse V2 complète est transitoire. Le journal seul conserve compteurs,
références et empreinte, ce qui permet d’établir la fin d’une tentative mais
limite la récupération du livrable.

Les qualifications historiques donnent des latences par brique et des essais
de reprise ciblés, dont un arrêt brutal réel en reconnaissance. Elles ne
permettent pas de sommer une latence globale ni d’attester la continuité d’une
mission longue. Cette campagne qualifie d’abord la chaîne de preuve et de
restitution. Un Skill Engine dépend d’un besoin de réutilisation mesuré.
L’évaluation commence via les bancs existants. Un Learning Engine dépend
d’évaluations reproductibles, d’une promotion humaine et du retour arrière.

Sources du bilan. [Consolidation recon](RECON_CONSOLIDATION.md),
[évaluation Juice Shop](../../benchmarks/web/README.md),
[revue M3.3](M33_SUPERVISED_REVIEW.md),
[mémoire M3.4](M34_MEMORY_ENGINE.md), [RAG M3.5.6](M356_RAG_EVALUATION.md),
[propositions typées](M3562_PROPOSITION_VALIDATION.md),
[consolidation M3.5.8](M358_KNOWLEDGE_CONSOLIDATION.md),
[architecture](../architecture/ARCHITECTURE.md) et [roadmap](ROADMAP.md).

## Parcours et décisions

Le protocole compare le résumé déterministe A, la revue V1 B, V2 sur archives
C, V2 et FTS5 D, V2 et NumPy 512D E, puis E et mémoire F. Une exécution de
référence et des contrôles documentaires séparent disponibilité, inclusion
dans le contexte, sélection et restitution. Les références de notation et
les mesures restent hors du contexte et du dépôt lorsque leur origine est
privée. Les essais hôte portent sur des fixtures locales à effets synthétiques.

Le bilan distingue intégrité, robustesse, coût et utilité. Une validation
d’utilité humaine exige des relecteurs humains indépendants et leur temps de
relecture. Sans cette validation, le bilan documente la mesure automatique
et laisse cette porte ouverte.
