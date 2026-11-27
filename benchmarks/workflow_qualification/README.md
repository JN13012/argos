# M3.5.9 — Banc du workflow intégré

Le [protocole](protocol.json) définit les bras A–F, l’objectif commun,
les budgets et les portes. Le banc utilise le code de restitution et
de revue de production, les fichiers M2.7.1 et la mémoire M3.4 validée.
Il lance deux Ollama préinstallés sur la boucle locale. Le générateur
est Qwen3 4B, et les embeddings Qwen3 512D utilisent le CPU. Les manifestes
et les blobs des deux modèles utilisés sont vérifiés. Aucun adaptateur
d’exécution de mission n’est lancé par le banc.

Depuis la racine, choisir un dossier privé existant pour le parent de
`--out`. Le dossier de destination doit être neuf pour chaque exécution.

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 .venv/bin/python -B \
  -m benchmarks.workflow_qualification.run \
  --archives .argos/qualifications/m271 \
  --memory data/qualification/m34/7ae823a6-3aeb-46e8-95d8-6480b09a83e8/memory \
  --ollama data/ollama --out data/qualification/m359/final
```

`--development` limite le rejeu à une paire par bras sur crAPI et identifie
le résultat comme développement. Avant toute inférence, le banc enregistre
`frozen.json`, ses empreintes et les attentes de notation. Les classes HTTP
viennent des reçus SQLite lus directement et des comptes figés. La
couverture historique vient des scores M2.7.1. Les définitions et les
contrôles documentaires proviennent de six notes synthétiques versionnées.
La note obsolète et la contradiction signalée vérifient la politique
d’assemblage. Ces jugements techniques n'évaluent pas une réponse en prose
et n'ont pas reçu de validation humaine indépendante.

Le banc produit des exports W6 vérifiés, un artefact de restitution privé
et un journal par tentative. La notation sépare les classes d’état
disponibles dans le paquet, celles choisies, celles rendues avec leur provenance,
les contradictions affichées et les inconnues préservées. V1 reçoit
l’objectif fixe de son contrat, qui est une synthèse d’archive, et
V2 reçoit l’objectif explicite du protocole. A sélectionne de manière
déterministe. Les bras partageant V2 gardent les mêmes budgets. Les entrées
de notation sont réservées à l’évaluateur. Les sorties complètes de V2
restent transitoires dans le produit. Leur enregistrement dans les artefacts
privés du banc sert à la notation et ne constitue pas une capacité produit.

Les bras et archives changent d’ordre d’un tour à l’autre. Chaque cellule
a trois paires, avec le modèle déchargé avant la première mesure puis
une seconde mesure en résidence. A répète dix paires par archive.
Les mesures sont froides au sens du modèle et de la vue en mémoire,
avec le cache de fichiers de l’OS en régime normal. A n’a aucun modèle.
Les p95 sont publiés à partir de 30 mesures. En dessous, l’effectif, la
médiane et la plage décrivent les observations. Les échantillons hôte
donnent la VRAM de la carte et la PSS et le CPU des groupes observables.
La PSS échantillonnée et le CPU des processus encore visibles ne sont
pas des mesures exhaustives des pics ou des processus très courts.
Le temps du banc inclut le snapshot, W6, les journaux et l’écriture privée.
L'attente avant le démarrage du banc et la construction de l’index ont
leurs propres périmètres.

L’agrégateur relit les traces locales et contrôle le protocole gelé.

```bash
.venv/bin/python -B -m benchmarks.workflow_qualification.report   data/qualification/m359/final > data/qualification/m359/assessment.json
```

Après le gel, le scénario de robustesse réutilise le fichier figé :

```bash
.venv/bin/python -B -m benchmarks.workflow_qualification.robustness \
  --frozen data/qualification/m359/final/frozen.json \
  --archive .argos/qualifications/m271/dvwa-contextual-r1/missions.sqlite \
  --out data/qualification/m359/robustness
```

Les arrêts proviennent de processus réellement tués au point de sélection
d’un fournisseur simulé. Le test d’indisponibilité passe par les vrais
adaptateurs vers un port local réservé sans écoute. Les altérations sont
injectées dans une copie. Les essais hôte complémentaires emploient les
fixtures HTTP bénignes déjà présentes. Ils restent distincts du rejeu et
des métriques de performance, et sont lancés séquentiellement.
