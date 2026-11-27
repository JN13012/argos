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

Le [protocole reproductible](../../benchmarks/workflow_qualification/README.md)
compare le résumé déterministe A, la revue V1 B, V2 sur archives
C, V2 et FTS5 D, V2 et NumPy 512D E, puis E et mémoire F. Une exécution de
référence et des contrôles documentaires séparent disponibilité, inclusion
dans le contexte, sélection et restitution. Les références de notation et
les mesures restent hors du contexte et du dépôt lorsque leur origine est
privée. Les essais hôte portent sur des fixtures locales à effets synthétiques.

Le bilan distingue intégrité, robustesse, coût et utilité. Une validation
d’utilité humaine exige des relecteurs humains indépendants et leur temps de
relecture. Sans cette validation, le bilan documente la mesure automatique
et laisse cette porte ouverte.

Le dénominateur de restitution HTTP est une classe de statut distincte par
archive et par essai. Le contrôle de preuve, lui, porte sur chaque reçu et
son empreinte. On compte séparément les faits disponibles dans le contexte,
ceux choisis par le sélecteur et ceux restitués avec leur statut et leur
preuve exacts. Les rapports W6 restent liés au run enregistré. Le snapshot
couvre aussi les preuves archivées en dehors de ce run de découverte.

Les notes synthétiques servent à localiser une omission documentaire entre
index, assemblage et sélection. Une contradiction signalée par un document
reste une déclaration de sa source. Le jugement ne valide ni la vérité de
la déclaration ni la résolution d’un conflit sémantique. Les contrôles
d’isolement et de changement documentaire utilisent des états construits dans
les fixtures, et les checks de production du journal et du snapshot lisent
des copies privées des archives.

## Campagne sur archives

Le banc figé au commit `1bbbe31bcfddfacba86095e7642566f3cb80fb28` a
exécuté **150 essais sur Python 3.14.6**. Le manifeste privé `frozen.json`
porte l’empreinte SHA-256
`dfaf60ac88a8ecf8e6c80d523cc2089f4ae3bd77ceb533bcd194bc8609414606`.
Les 90 analyses B–F ont utilisé de vrais Ollama locaux. Les deux régimes
de résidence ont été observés avant chaque appel. Les 150 essais
aboutissent. À chaque essai, tous les reçus du snapshot correspondent au
référentiel de l’archive et les trois exports W6 se vérifient. Cela couvre
58 reçus distincts Juice Shop, 38 crAPI et 37 DVWA. Les index W6 des runs
correspondants contiennent respectivement 24, 4 et 3 reçus. Les empreintes
des sources contrôlées sont identiques avant et après les essais.

Le tableau donne les résultats **à chaud** pour les faits et les passages.
Chaque cellule B–F compte neuf essais à chaud et neuf à froid. A compte 30
essais par régime. Les résultats de sélection et de restitution des classes
HTTP sont identiques entre chaud et froid. Les plages des deux régimes sont
en secondes et suivent l’ordre médiane [minimum–maximum].

| Bras | Intégrité et état terminal | Classes HTTP disponibles → choisies → restituées | Passages pertinents récupérés → inclus → cités | Froid | Chaud |
| --- | ---: | --- | --- | ---: | ---: |
| A — Déterministe | 60/60 | 40 → 40 → 40 / 90 | Sans corpus | 0,95 [0,55–3,65] | 0,96 [0,54–3,34] |
| B — V1 | 18/18 | 12 → 12 → 12 / 27 | Sans corpus | 11,50 [8,04–12,36] | 3,75 [2,96–8,27] |
| C — V2 archive seule | 18/18 | 27 → 15 → 15 / 27 | Sans corpus | 12,33 [9,22–17,85] | 5,62 [3,91–14,65] |
| D — V2 FTS5 | 18/18 | 24 → 9 → 9 / 27 | 21 → 21 → 0 / 21 | 11,80 [9,55–21,39] | 5,89 [3,84–13,25] |
| E — V2 NumPy 512D | 18/18 | 24 → 9 → 9 / 27 | 21 → 21 → 0 / 21 | 14,18 [11,20–22,49] | 5,29 [4,52–13,79] |
| F — E et mémoire | 18/18 | 24 → 9 → 9 / 27 | 21 → 21 → 0 / 21 | 12,75 [11,02–21,72] | 6,36 [4,64–12,78] |

Le volet critique est restitué à chaque essai. Il totalise 460 occurrences
de faits classés inconnus ou contradictoires dans A et 138 par bras B–F.
Aucun statut restitué n’est lié à une preuve incorrecte. D–F conservent
la contradiction documentaire déclarée et omettent le passage obsolète
dans les 54 essais concernés. Le statut d’abstention V2 est partiel pour
les 18 essais C. D, E et F présentent chacun 12 abstentions totales et
6 partielles. La campagne établit le traitement de ces entrées et de
ces étiquettes, sans note de raisonnement sémantique libre.

### Contribution par composant

- **State et Evidence.** Le snapshot vérifie les 133 reçus distincts et
  leurs empreintes sur ces archives. W6 permet de relire et vérifier trois
  exports du run. L’inventaire HTTP du snapshot et l’index W6 ont des
  périmètres distincts. Le résumé compact A affiche quatre des neuf classes
  HTTP du référentiel commun par répétition complète. Sa synthèse n’est
  donc pas une restitution exhaustive des reçus.
- **Contexte et analystes.** B restitue les mêmes classes qu’A en
  proportion et conserve ses 18 restitutions dans le journal. C augmente
  la disponibilité des classes de 12/27 à 27/27, puis n’en restitue que
  15/27. Les classes disponibles écartées par le modèle restent le principal
  écart entre la preuve et la synthèse. La relecture V2 vérifie le journal
  et l’empreinte de la réponse, avec zéro contenu intégral récupérable
  pour les 72 essais C–F.
- **Knowledge.** D et E retrouvent toutes les définitions pertinentes du
  petit corpus et les transmettent. La sélection ne cite aucune définition
  pertinente. L’ajout documentaire occupe une partie du contexte, qui
  passe de 27 à 24 classes HTTP disponibles. La sélection perd encore
  des classes et restitue neuf classes contre quinze pour C. Cette
  comparaison n’autorise pas à classer les retrievers sur un corpus large.
- **Memory.** F atteint les mêmes scores de restitution qu’E sur les
  18 paires et transmet **zéro unité mémoire** après assemblage. L’effet
  mesuré porte sur ces archives et cette politique de déduplication.
- **Utilité opérateur.** La couverture des classes augmente de 12/27 à
  15/27 entre B et C, ce qui dépasse la taille de gain proposée sur ce
  proxy. Il n’y a eu ni revue humaine indépendante ni mesure du temps
  opérateur. La porte d’utilité reste ouverte et le contenu V2 demeure
  transitoire. A est la référence déterministe pour contrôler les preuves,
  avec ses omissions visibles. B reste une option supervisée. C–F ne
  franchissent pas les portes de restitution et d’adoption par défaut.

### Performances et profil matériel

Sur 30 mesures par régime, A a un p95 de **3,63 s** en première lecture et
**3,30 s** en lecture suivante. Une mesure froide signifie ici modèle
déchargé et vue NumPy reconstruite, avec cache de fichiers normal. B–F
ont neuf mesures par régime. Les données sont descriptives, ce qui ne
permet pas de vérifier le plafond comparatif de +25 % de p95 à chaud.
Le plafond absolu froid de 45 s est respecté pour les 150 essais finaux.
Le développement a enregistré un premier refus de configuration de
résidence, corrigé avant le gel. Il a aussi observé un démarrage froid
V1 à 52,7 s. Les deux traces restent hors du jeu final.

| Mesure à chaud, médiane | A | B | C | D | E | F |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Snapshot initial | 907 ms | 859 ms | 850 ms | 847 ms | 799 ms | 964 ms |
| Exports W6 et vérification | 45 ms | 55 ms | 58 ms | 42 ms | 45 ms | 57 ms |
| Vérification W6 seule | 21 ms | 27 ms | 34 ms | 20 ms | 20 ms | 27 ms |
| Création du journal | — | 879 ms | 885 ms | 1 004 ms | 847 ms | 1 038 ms |
| Relecture du journal | — | 16 ms | 20 ms | 20 ms | 18 ms | 20 ms |
| Archive et mémoire pendant V2 | — | — | 775 ms | 873 ms | 802 ms | 898 ms |
| Récupération documentaire | — | — | 0 ms | 8 ms | 295 ms | 261 ms |
| Assemblage V2 | — | — | 5 ms | 6 ms | 7 ms | 9 ms |
| Sélection Ollama V2 | — | — | 1 109 ms | 1 040 ms | 979 ms | 1 062 ms |
| Validations V2 avant et après sélection | — | — | 1 708 ms | 1 651 ms | 1 519 ms | 1 789 ms |

Les médianes des étapes ne s’additionnent pas. B mesure l’appel fournisseur
avec validation à 1,27 s à chaud et 6,02 s à froid. La construction de
l’index du corpus de six fragments prend 4,83 s, hors essais. Dans V2,
la relecture et la validation des magasins coûtent davantage que
l’assemblage. Le coût médian du dense est supérieur à celui de FTS5 sur
ce corpus, avec des durées globales sensibles à la variabilité des
autres étapes.

Les tokens médians entrée/sortie sont de **761/42** pour B, **1 875/27**
pour C, **1 875/20** pour D et E et **1 885/23,5** pour F. Les journaux
par revue occupent 368 à 1 172 Kio, selon l’archive et le bras. Les
artefacts cumulés représentent 77 Mio, copies comprises. Le CPU agrégé
du processus du banc par essai a des médianes de 1,17 s pour A, 4,08 s
pour B et 6,29 à 6,42 s pour C–F, sur les deux régimes. Les mesures CPU
et mémoire tiennent compte des processus visibles pendant l’échantillonnage.
Les variations positives des compteurs échantillonnés du groupe générateur
totalisent, en médiane selon le bras, 7,19 à 8,53 s CPU à froid et 1,04 à
1,36 s CPU à chaud. Pour E–F, le groupe d’embeddings cumule 8,04 à 9,67 s
CPU à froid et 3,68 à 3,80 s CPU à chaud. Ces estimations omettent le
travail entre les bornes d’échantillonnage et les processus trop courts.

**Profil recommandé.** Faire tourner A sur CPU et activer Ollama pour une
revue consultative explicitement demandée. Le profil de cette campagne
utilise 16 CPU logiques visibles, environ 15,2 Gio de RAM hôte, Qwen3 4B
sur RTX 4060 Laptop 8 Gio et les embeddings sur CPU. Le pic VRAM
échantillonné de la carte est de 4 269 Mio. Le pic PSS simultané du banc
et des deux groupes Ollama est d’environ 4 754 Mio. Le profil n’établit
pas un minimum matériel. La présence d’un modèle résident pendant
certains essais A n’est pas une consommation GPU demandée par A.

Les traces sont dans `data/qualification/m359/final/` et la matrice
agrégée dans `data/qualification/m359/assessment.json`, hors Git. Les
armes de comparaison et le protocole viennent du banc décrit plus haut.

### Reprise et isolation

Les essais hôte ciblés distinguent six cas à worker réel et dix cas de
fixture. Sur le vrai chemin HTTP, un serveur local renvoie des réponses
bénignes. Les tests couvrent reçus expurgés, révocation pendant requête
et panne simulée au commit. Le contrôle de révocation vérifie un
arrêt en moins de 1,5 s après le retrait. Pour la panne de commit, le serveur voit une
seule requête et le travail reste interrompu. Les tests du worker sans
réseau couvrent aussi le cloisonnement du système de fichiers et le
nettoyage des descendants après la mort du processus parent. Les autres
cas portent sur l’intégrité des exports, les permissions et identités de
mémoire, le retrait ou la révocation documentaire, le repli lexical
simulé et les sorties tardives. Aucun essai n’utilise les laboratoires
d’origine en réseau.

Le scénario de volume utilise une copie DVWA de 956 Kio et 128
annotations synthétiques de 4 Kio. Sur Python 3.14, le journal augmente
de **356 à 936 Kio**. La relecture, sur 30 mesures à chaque point, passe
de **8,21 à 14,15 ms** en médiane et de **13,17 à 19,52 ms** au p95.
Deux processus de revue sont réellement interrompus par `SIGKILL` à
l’entrée d’un sélecteur simulé. Après redémarrage, le journal montre
`analyzing` jusqu’à la décision explicite d’interrompre, enregistrée
en **84,5 puis 74,5 ms**. Le numéro de tentative ne change pas au
marquage de l’interruption. La nouvelle tentative explicite termine
en **1,95 s**. Le scénario mesure le volume du journal et la reprise du
processus. La durée d’une mission réelle de plusieurs heures et le
volume maximal des preuves restent à mesurer.

L’injection d’une empreinte altérée dans la copie est refusée. Une
perte simulée de la sortie V2 laisse l’état `ready` et l’empreinte
valides, avec la restitution complète indisponible. Les deux vrais
adaptateurs Ollama face à un port local sans écoute rendent
`provider_unavailable`. V1 journalise `failed` avec une tentative.
V2 laisse `created` et zéro tentative. Le refus se produit pendant
l’identification du modèle, avant la journalisation de l’analyse.
Ce cas distingue l’arrêt sûr de la traçabilité opérateur.

### Décisions et dette priorisée

| Porte | Conclusion |
| --- | --- |
| Intégrité des preuves et rapports | Réussie pour les trois archives et les exports produits. L’altération est refusée sur copie. |
| Reprise et cloisonnement | Exercés sur les fixtures décrites. Les reprises de revue restent explicites. Une requête déjà reçue sur la fixture HTTP et les écritures synthétiques au résultat incertain ne sont pas rejouées dans les contrôles exercés. |
| Récupération de la restitution | V1 récupère le contenu. V2 récupère l’état et l’empreinte. C–F restent non qualifiés pour la récupération intégrale sur perte de sortie. |
| Utilité et coût d’un nouveau mode par défaut | Porte humaine ouverte. Le p95 comparatif des modes B–F reste non évalué. Aucun nouveau mode n’est retenu par défaut. |
| Périmètre produit | Qualification sur archives et fixtures. Les résultats restent hors évaluation de couverture W8 et hors reprise d’un plan de mission W7. |

1. **P1 — Rendre le livrable V2 récupérable.** Définir un artefact privé
   lié atomiquement à la décision de restitution, avec droit de lecture,
   politique de rétention et contrôle d’intégrité. Tester la coupure
   entre l’état `ready` et la remise de la sortie. Journaliser
   explicitement les refus antérieurs à l’inférence, dont une panne
   d’identification du modèle.
2. **P1 — Garantir la visibilité des faits d’archive.** Les omissions
   apparaissent dans l’assemblage compact et dans la sélection. Mesurer
   séparément ces deux étapes. Utiliser les classes attestées et leurs
   références pour les évaluations automatiques de restitution.
3. **P2 — Revoir la validation répétée et le coût documentaire.**
   Mesurer la relecture des mêmes preuves et journaux à volume croissant.
   Préserver le refus sur changement de révision. Retenir FTS5 comme
   comparaison économique pour un nouveau corpus indépendant. Le dense
   et la mémoire demandent une preuve d’apport marginal.
4. **P2 — Évaluer l’opérateur.** Faire annoter des objectifs réservés
   par des relecteurs indépendants. Mesurer le temps de validation, la
   précision des références utiles et les pertes critiques. Garder
   le sélecteur extractif et les verdicts libres dans des évaluations
   distinctes.
5. **P3 — Garder le Skill Engine en attente.** Les résultats orientent
   d’abord la fiabilité de restitution et l’évaluation ciblée. Les
   évaluateurs existants suffisent à cette tranche. Réexaminer Learning
   après une série comparative indépendante et une promotion réversible.

### Validation locale

| Vérification | Python 3.12.15 | Python 3.14.6 |
| --- | --- | --- |
| Suite régulière `python -m pytest -q -o faulthandler_timeout=30` | 1 448 réussis, 121 ignorés en 128,55 s | 1 448 réussis, 121 ignorés en 136,97 s |
| Sélection de fixtures et vrais workers sur boucle locale | 16 réussis en 8,92 s | 16 réussis en 10,17 s |
| Rejeu A–F avec Ollama installé | 12/12 sur crAPI, une paire par bras. Contrôle de compatibilité. | 150/150 sur trois archives. Campagne statistique principale. |
| Copie DVWA, deux arrêts réels et sélecteur simulé | Reprise explicite en 1,90 s. Marquages en 76,0 et 58,2 ms. | Reprise explicite en 1,95 s. Marquages en 84,5 et 74,5 ms. |
| Journal simulé à volume croissant | p95 de 15,77 à 23,44 ms sur 30 lectures par point. | p95 de 13,17 à 19,52 ms sur 30 lectures par point. |

Ruff, formatage, Pyright sur les sources et sur le banc, vérification
des liens locaux et `git diff --check` réussissent. Les tests optionnels
ignorés par les suites régulières gardent cette portée. Aucun autre
profil réseau, navigateur ou registre n’est qualifié par ces essais.
Les traces du contrôle Python 3.12 sont dans
`data/qualification/m359/compatibility-312/`. Elles ne sont pas regroupées
avec la campagne principale. Les 176 fichiers du manifeste historique
M2.7.1 correspondent encore à
leurs empreintes. Le banc a vérifié les archives, la mémoire et les
actifs Ollama retenus avant et après l’exécution. Les sources produit
et les dépendances sont identiques au SHA de base.
