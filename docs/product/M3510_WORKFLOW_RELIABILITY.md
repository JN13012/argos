# M3.5.10 — Fiabilité du workflow intégré

Base `4569f463b976a19771492b1ddc209897fcc54098` sur
`feat/m359-workflow-qualification`. Le contrôle initial donnait un arbre
propre, aucun commit postérieur à ce SHA et `main` à `74b3221`.
La tranche traite la restitution V2 et les échecs de tentative relevés
en [M3.5.9](M359_WORKFLOW_QUALIFICATION.md).

## Restitution V2 récupérable

Le journal SQLite privé contient une table additive de restitutions.
L’événement terminal `ready`, la mise à jour de la tête et l’insertion
du JSON de restitution partagent une transaction. La ligne est liée à
l’empreinte de l’événement terminal. Celui-ci lie le condensat du JSON,
la tentative et l’événement de contexte préparé. Une erreur de stockage
laisse la tentative active pour interruption explicite. Les extraits
et affirmations effectivement rendus sont conservés dans ce stockage,
tandis que l’appel brut du modèle et le paquet transmis restent
transitoires. La rétention suit celle du journal privé. Les sauvegardes
du journal incluent désormais les restitutions et exigent les mêmes
protections d’accès.

```bash
python -m argos review workflow-restitution-v2 \
  --db ARCHIVE.sqlite --journal REVUES.sqlite --review-id UUID
```

Pour un contexte enrichi, fournir les mêmes collections et, le cas
échéant, le même périmètre mémoire qu’à l’analyse. Par défaut, la
commande récupère la dernière tentative V2 réussie de cette revue.
`--attempt-sha256` sélectionne une tentative réussie précise,
indépendamment de l’état courant de la revue. `--expected-head` contrôle
un point de contrôle externe si l’opérateur l’a conservé. La lecture
vérifie les fichiers privés, l’intégrité du journal, le lien avec la
tentative et les permissions et références courantes. Un snapshot,
une tête mémoire ou une génération documentaire modifiés imposent
une nouvelle revue. Une collection révoquée ou un extrait retiré
bloque la lecture. La lecture utilise les lecteurs locaux existants
et fonctionne sans Ollama. `workflow-show` expose les métadonnées
de revue et n’inclut pas les restitutions V2.

Les journaux V1 et les événements V2 historiques restent lisibles.
Une tentative historique produite sans stockage retourne
`historical_restitution_unavailable`. Une tentative annoncée comme
persistée, dont le contenu est absent ou altéré, échoue à l’intégrité.
Une ancienne restitution perdue n’est pas reconstruite.

## Cycle de tentative

Après validation du périmètre local, `analyzing` est journalisé avant
l’identification d’Ollama. `prepared` fixe ensuite le modèle, le budget
et les références du contexte sous la même tentative. Les erreurs
sont journalisées avec une phase parmi `identify`, `prepare_context`
et `inference`. Une interruption avant ou après la préparation peut
être enregistrée explicitement après redémarrage. Une autre tentative
démarre uniquement à la demande. Un résultat tardif ne peut pas publier
`ready` après le changement de tête de la revue.

## Qualification

Le [banc](../../benchmarks/workflow_qualification/README.md) rejoue
une paire froide/chaude par archive et par bras A–F. La comparaison
emploie la première paire M3.5.9 de chaque cellule et le même
dénominateur de neuf classes HTTP par régime pour chaque bras.
La récupération est chronométrée après la fenêtre comparable.
Sur D chaud, les contrôles de sélection réutilisent les candidats du
paquet réellement transmis et gardent le modèle et le format de
réponse. Ils font varier l’objectif, l’ordre des passages et la
présence des autres catégories de candidats. Les mesures contrefactuelles
sont distinctes du parcours normal.

### Diagnostic de sélection

| Contrôle sur le bras D chaud | crAPI | DVWA | Juice Shop |
| --- | ---: | ---: | ---: |
| Passages pertinents présents dans le paquet | 1 | 3 | 3 |
| Rejeu du même paquet | 0 | 0 | 0 |
| Objectif explicite, ordre identique | 0 | 0 | 0 |
| Même objectif et mêmes candidats, passages en tête | 1 | 3 | 3 |
| Passages seuls | 1 | 3 | 3 |

**Budget.** Dans le parcours normal, le contexte C expose neuf classes
de statut et D à F en exposent huit sur les mêmes trois archives.
Une partie de l’inventaire est écartée avant sélection. Le budget
V2 nominal permet 48 éléments et 32 768 octets. Les paquets D à chaud
sont en deçà de ces limites et approchent la borne conservatrice d’entrée
de 7 808 tokens, qui assimile les octets au coût d’entrée. Ollama compte
en réalité 1 872 à 1 884 tokens sur ces paquets. Un contrôle
d’assemblage sans modèle porte la limite d’éléments à 96, sans changer
les classes présentes. En doublant seulement la fenêtre, le statut
301 revient dans le paquet DVWA. Les sept passages pertinents
atteignent déjà le modèle avec le budget normal.

**Format et restitution.** Les 12 sorties contrefactuelles respectent le
format des références numériques. Le schéma accepte les identifiants
documentaires. Les contrôles de restitution associent un identifiant de
passage sélectionné à son extrait exact et à sa citation. Les documents
absents des réponses ordinaires sont déjà absents de la sélection.

**Sélection.** En entrée mixte, les contrôles à objectif constant
sélectionnent les sept passages pertinents dès qu’ils passent en tête.
Le nombre de tokens d’entrée mesurés reste identique pour le rejeu et
le réordonnancement de chaque paquet. Le sélecteur utilise huit
références sur les paquets mixtes. La seule reformulation de l’objectif
change les sélections mais conserve zéro passage pertinent. L’ordre et la numérotation
associée des candidats sont donc un facteur démontré sur ce corpus. Le contrôle
« passages seuls » réduit à la fois la concurrence et la taille du
paquet. Il confirme la capacité de sélection documentaire sans
isoler ces deux effets.

Cette observation porte sur trois paquets construits à partir de six
notes synthétiques. Elle justifie un essai ciblé de composition et d’ordre
du contexte sur un jeu indépendant avant une adoption. Il n’y a pas eu
de modification du modèle, des embeddings ou du retrieval. La revue
humaine indépendante reste ouverte.

### Résultats avant/après

Les 36 essais A–F aboutissent et vérifient les reçus d’archive et les
trois exports W6. Les 24 réponses V2 nouvelles sont récupérées à
l’identique depuis le stockage privé, sans nouvel appel au modèle.
Une vraie revue M3.5.9 relue via le nouveau CLI retourne
`historical_restitution_unavailable`. Le journal historique garde son
état `ready` et ses octets.

| Bras | Classes HTTP disponibles après, sur 9 | Classes HTTP restituées avant → après, sur 9 | Médiane froide avant → après | Médiane chaude avant → après |
| --- | ---: | ---: | ---: | ---: |
| A | 4 | 4 → 4 | 0,93 → 1,18 s | 0,83 → 1,25 s |
| B | 4 | 4 → 4 | 11,50 → 14,29 s | 4,09 → 4,42 s |
| C | 9 | 5 → 5 | 13,08 → 13,20 s | 5,81 → 7,71 s |
| D | 8 | 3 → 3 | 13,99 → 14,44 s | 5,89 → 7,45 s |
| E | 8 | 3 → 3 | 16,27 → 20,33 s | 6,30 → 7,56 s |
| F | 8 | 3 → 3 | 17,81 → 14,81 s | 6,36 → 5,43 s |

Les classes HTTP ont les mêmes comptes à froid et à chaud. Chaque
médiane regroupe trois cas appariés par régime. Les durées excluent
la récupération, les contrôles de sélection et le chargement initial du
banc. Le témoin A évolue lui aussi entre les campagnes. Les écarts
reflètent deux sessions distinctes et restent descriptifs. La mesure
évite d’attribuer tout l’écart au stockage et ne publie aucun p95
comparatif sur trois points.

La récupération V2 prend **0,61 à 2,62 s** sur les 24 tentatives. Les
médianes par bras sont de **1,01 s** pour C, **1,07 s** pour D, **0,89 s**
pour E et **0,86 s** pour F. Ce temps comprend la vérification du journal
et des références. Le journal d’une revue V2 gagne de 12 à 20 Kio
sur ces paires, avec une médiane de 12 Kio. Le workflow recommande toujours A pour les contrôles
d’intégrité et B en option supervisée. Les nouvelles garanties de
récupération V2 ne changent pas les résultats d’utilité consultative.

### Échecs et reprise sur copie

Le port Ollama réservé sans écoute exerce les vrais adaptateurs. V2
passe de `created` sans tentative en M3.5.9 à `failed` avec une
tentative, la phase `identify` et `provider_unavailable`. Un test avec
sélecteur simulé force la même indisponibilité en phase `inference`.
Il vérifie la liaison à la tentative, puis la réussite d’une troisième
tentative explicitement demandée après les deux échecs.

Le scénario de reprise tue deux vrais processus sur la même copie DVWA.
Le premier se bloque pendant l’identification du modèle simulé. Le
second se bloque à la sélection, après préparation du contexte. Après
chaque arrêt, le journal expose `analyzing` puis `interrupted` à la
demande. Le nombre de tentatives reste inchangé au marquage. La troisième
tentative termine après reprise explicite. Un autre processus CLI,
sans fournisseur actif, relit sa restitution exacte et son point de
contrôle. Le scénario refuse aussi une empreinte de reçu altérée.
Les contrôles logiciels couvrent la révocation documentaire, l’altération
du contenu et le retour arrière de la transaction lors d’un échec
d’insertion. Ils vérifient qu’une réponse tardive ne crée aucune
restitution après interruption.

### Validation locale

| Contrôle | Python 3.12.15 | Python 3.14.6 |
| --- | --- | --- |
| Suite régulière `python -m pytest -q -o faulthandler_timeout=30` | 1 452 réussis, 121 ignorés en 118,42 s | 1 452 réussis, 121 ignorés en 126,45 s |
| Marquages explicites après les deux arrêts | 59,4 puis 55,2 ms | 53,8 puis 52,0 ms |
| Nouvelle tentative avec sélecteur simulé | 1,59 s | 1,57 s |
| Récupération dans un nouveau processus CLI, démarrage inclus | 1,18 s | 1,08 s |

La campagne de rejeu avec Ollama et les contrôles de sélection ont
été exécutés sur Python 3.14.6 au commit `96f10ac`. Le banc
et les sources passent Ruff, formatage et Pyright. Les contrôles
de liens locaux et `git diff --check` passent. Les tests hôte
optionnels ignorés en suite régulière gardent leur statut.
Le rejeu M3.5.10 cible le workflow de revue et les copies. Les essais
de workers réels qualifiés en M3.5.9 restent historiques.

### Préparation de l’intégration

La branche contient l’audit et la campagne M3.5.9, les deux corrections
M3.5.10, le banc de diagnostic et ce bilan. Le `main` local reste au SHA
`74b3221f8120a6cd0d3365eff2a13b2a35d74280` et est son ancêtre. Le diff
ne contient que le code de revue, les contrôles, le banc et la
documentation. Les sorties privées sont sous
`data/qualification/m3510/`, avec les archives, la mémoire et les actifs
Ollama vérifiés avant et après la campagne. Il n’y a eu ni nouveau scan
ni téléchargement.

L’intégration attend la décision de validation. Les anciens journaux
restent lisibles et la table additive est créée au premier succès V2.
La sauvegarde d’un journal de revue inclut désormais les restitutions
privées. La compatibilité qualifiée porte sur l’ouverture des journaux
historiques par le nouveau code. Le pilote de revue humaine et tout
changement de sélection restent des décisions séparées.
