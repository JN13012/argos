# Argos — Références et sélection de briques

## Dossier initial du 16 novembre 2026

La cible est une mission autonome complète, conformément à la [vision](VISION.md).
Une dépendance publique peut accélérer une capacité ; construire un composant
propre reste une option. Aucun des candidats ci-dessous n’est intégré par P0.

Cette première sélection vérifie l’identité du dépôt, sa branche par défaut et
son head, puis les métadonnées et les conditions de licence accessibles.
Hermes, Nuclei, SpiderFoot, Temporal et les données CVE ont aussi été examinés à
travers leur README. Il ne s’agit pas d’un audit de leur code, d’un benchmark ou
d’une preuve de compatibilité avec Argos. Les commits sont des repères consultés,
pas des versions qualifiées pour la production. Les branches et licences
doivent être revérifiées pour les fichiers effectivement adoptés.

| Dépôt officiel | Rôle | Licence / conditions consultées | Intérêt et limite pour Argos | Head de référence |
| --- | --- | --- | --- | --- |
| [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) | Agent / harness | [MIT](https://github.com/NousResearch/hermes-agent/blob/611f0ab757b307774c4a63c7b19f67d1f3aa6f6e/LICENSE) | Boucle agentique, mémoire, skills et délégation ; comparer à un moteur Argos propre. Terminal générique et apprentissage ne valent pas contrôle de mission ; passer uniquement par les capacités Argos. | [611f0ab757b3](https://github.com/NousResearch/hermes-agent/commit/611f0ab757b307774c4a63c7b19f67d1f3aa6f6e) |
| [temporalio/sdk-python](https://github.com/temporalio/sdk-python) | Workflow durable | [MIT](https://github.com/temporalio/sdk-python/blob/968c3c9dcf508ceca3f4e34b9ea910425351f6c5/LICENSE) | Étudier checkpoints, activités et reprise pour les longues missions. Un moteur de workflow ne remplace ni le raisonnement ni la politique ; évaluer le coût d’un serveur et l’idempotence des reprises. | [968c3c9dcf50](https://github.com/temporalio/sdk-python/commit/968c3c9dcf508ceca3f4e34b9ea910425351f6c5) |
| [OWASP/wstg](https://github.com/OWASP/wstg) | Méthodologie web | [CC-BY-SA-4.0](https://github.com/OWASP/wstg/blob/31d781011ca0d03c89be0489de2400eef35cd5de/LICENSE) | Structurer les cas d’essai et leurs conditions de validation. Adapter les cas au scope, conserver versions et attribution ; un guide n’est pas un runner. | [31d781011ca0](https://github.com/OWASP/wstg/commit/31d781011ca0d03c89be0489de2400eef35cd5de) |
| [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | Référentiel ATT&CK | [Licence MITRE spécifique](https://github.com/mitre-attack/attack-stix-data/blob/a8db2f52eb933c9c99060c123e088b3326d3a607/LICENSE.txt) | Importer des identifiants et relations STIX versionnés pour indexer techniques et couverture. ATT&CK décrit des comportements ; une correspondance ne prouve pas une compromission ni une couverture exhaustive. | [a8db2f52eb93](https://github.com/mitre-attack/attack-stix-data/commit/a8db2f52eb933c9c99060c123e088b3326d3a607) |
| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | Données CVE | [Conditions du programme CVE](https://www.cve.org/Legal/TermsOfUse) | Alimenter un cache de fiches CVE officielles et de versions de schéma. Une bannière de service ne prouve pas l’applicabilité ; traiter les mises à jour et les références externes. | [1e4dc4a29028](https://github.com/CVEProject/cvelistV5/commit/1e4dc4a290287759e30c36836cc73f80dd56a57a) |
| [cisagov/kev-data](https://github.com/cisagov/kev-data) | Priorisation KEV | [CC0-1.0 pour la base](https://github.com/cisagov/kev-data/blob/a795af4c4afc47df12906b4c04e656156cf06493/LICENSE) | Enrichir les constats applicables avec le catalogue des vulnérabilités exploitées connues. Distinguer priorité et exploitabilité sur la cible ; les liens tiers gardent leurs propres conditions. | [a795af4c4afc](https://github.com/cisagov/kev-data/commit/a795af4c4afc47df12906b4c04e656156cf06493) |
| [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | Tests spécialisés | [MIT pour le moteur](https://github.com/projectdiscovery/nuclei/blob/1a762d9f9177b1f35e89e10c3de5502f1e40712d/LICENSE.md) | Candidat à un adaptateur typé produisant des résultats normalisés et des preuves. Revoir séparément chaque template et sa licence ; borner scope, effets, débit, réseau et version. | [1a762d9f9177](https://github.com/projectdiscovery/nuclei/commit/1a762d9f9177b1f35e89e10c3de5502f1e40712d) |
| [owasp-amass/amass](https://github.com/owasp-amass/amass) | Découverte d’actifs | [Apache-2.0](https://github.com/owasp-amass/amass/blob/a284d25a890cbb561a53410080a3fd96bbaa7312/LICENSE) | Évaluer la découverte et la cartographie de surface externe comme adaptateur. Séparer collecte passive et active, API externes, clés et nouveaux actifs hors mandat. | [a284d25a890c](https://github.com/owasp-amass/amass/commit/a284d25a890cbb561a53410080a3fd96bbaa7312) |
| [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | OSINT modulaire | [MIT](https://github.com/smicallef/spiderfoot/blob/0f815a203afebf05c98b605dba5cf0475a0ee5fd/LICENSE) | Étudier les connecteurs, la corrélation et les exports de données OSINT. Compatibilité et maintenance à qualifier : le head master consulté date de 2023 malgré des pushes plus récents sur le dépôt. | [0f815a203afe](https://github.com/smicallef/spiderfoot/commit/0f815a203afebf05c98b605dba5cf0475a0ee5fd) |
| [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Cycle de vie des constats | [BSD-3-Clause](https://github.com/DefectDojo/django-DefectDojo/blob/f6cee25f3e0fca85c8ccfc6e3764a4e69a2f0c0f/LICENSE.md) | Étudier déduplication, import des résultats, remédiation et recontrôle. Décider entre intégration et modèle propre ; éviter d’importer tout un produit pour un contrat étroit. | [f6cee25f3e0f](https://github.com/DefectDojo/django-DefectDojo/commit/f6cee25f3e0fca85c8ccfc6e3764a4e69a2f0c0f) |

Les licences de code, templates, contenus, données et dépendances sont à traiter
séparément. La disponibilité publique ne suffit pas à autoriser toute reprise.
Les notices applicables seront conservées avec les composants réellement
adoptés ; aucun code ou jeu de données tiers n’est copié dans cette étape.
Pour CVE, le README renvoie aux conditions du programme ; la page de conditions
nécessite un rendu JavaScript et n’a pas été vérifiée intégralement ici. Les
droits précis des données restent donc à qualifier avant adoption.

## Hermes ou un moteur propre

Hermes est un candidat réel : son README décrit une boucle d’apprentissage,
mémoire/skills, délégation et plusieurs environnements d’exécution. Ce sont des
fonctions à vérifier dans un essai, pas des garanties d’autonomie cyber fiable.
Le shell générique et la promotion automatique de méthodes ne doivent pas
contourner les contrôles Argos.

Comparer deux prototypes derrière la même interface :

1. Un adaptateur Hermes limité au registre de capacités Argos.
2. Une boucle Argos propre, avec les mêmes modèles, outils, observations,
   budgets et objectifs.

La politique de mission et la production de preuves appartiennent à Argos.
L’agent peut enchaîner seul les actions déjà autorisées. Il ne s’octroie ni
permissions supplémentaires, ni accès direct aux runners historiques ou à un
shell généraliste hors de ce registre.

Scénarios d’acceptation : mission nominale, prérequis manquant, cible hors scope,
observation portant des instructions hostiles, panne du fournisseur, annulation,
révocation, dépassement de budget et reprise après arrêt. Mesurer réussite de
mission, preuves vérifiables, faux positifs/omissions, temps, coût, interventions
humaines et effort de maintenance. Fixer les seuils avant d’exécuter les essais ;
choisir ensuite adoption, adaptation ou construction propre. Aucun vainqueur
n’est déclaré dans ce dossier.

## Workflow, connaissance et données : rôles distincts

Un moteur de workflow durable, tel que Temporal, fournit des mécanismes de
reprise ; il ne remplace pas l’agent. Toute reprise doit éviter les doublons
d’actions réseau. Comparer son coût d’exploitation à un état local persistant
avant de l’adopter.

La méthodologie, les observations et les référentiels restent séparés :

- WSTG : cas de test web et conditions d’évaluation.
- ATT&CK : techniques/comportements, identifiants et relations de connaissance.
- CVE : identifiants et fiches de vulnérabilités ; conserver le schéma déclaré.
- CWE : catégories de faiblesse, distinctes des CVE.
- CVSS : mesure de sévérité, distincte d’une preuve d’applicabilité.
- KEV : information d’exploitation connue pour prioriser des constats pertinents.

Une version détectée ou une correspondance dans un référentiel reste une piste
jusqu’à validation sur la cible autorisée. Les rapports doivent conserver source,
version, date de collecte, couverture et limites. La sélection initiale ne
promet aucune supériorité mesurée des outils OSINT.

## Ordre proposé des essais

Après P1, commencer par le registre de capacités et le catalogue original.
Comparer ensuite Hermes au moteur propre sur une petite mission autonome.
Qualifier les adaptateurs de découverte et de test séparément. Les données
ATT&CK/CVE/KEV et la gestion des constats peuvent enrichir progressivement les
résultats ; elles ne doivent pas remplacer la validation.

Enum2Root et PromptLab restent des références fonctionnelles locales, décrites
dans l’[audit initial](AUDIT_2026-11-16.md). Leur reprise éventuelle nécessite
d’établir les droits et la provenance des fichiers concernés.

## Veille antérieure conservée

Les références ci-dessous proviennent de la veille initiale et ne sont pas
requalifiées par la sélection du 16 novembre. Elles restent des pistes d’étude.

Ces références servent à étudier des idées de conception pour les domaines
futurs. Elles ne définissent pas le scope actif. Les liens sont issus de la
veille existante, complétée par l'identification de LoganSec ; cette passe
n'évalue pas les outils, leurs performances ou leurs licences actuelles.

| Projet | Intérêt pour Argos / idées à étudier | Ce qu'il ne faut pas copier aveuglément |
| --- | --- | --- |
| [XBOW](https://docs.xbow.com/console/get-started/introduction/) | Restitution lisible et lien entre résultat et éléments justificatifs | Promesses d'autonomie, performances annoncées ou périmètre offensif |
| [Strix](https://github.com/usestrix/strix) | Parcours développeur et présentation des résultats | Architecture et outillage complets avant un besoin démontré |
| [NoScope](https://www.noscope.com/) | Supervision humaine, revue et contrôle du périmètre | Modèle de permissions supposé suffisant sans validation propre |
| [Pentera](https://pentera.io/pentera-platform/) | Priorisation et suivi des corrections | Hypothèse qu'un score ou une observation valide techniquement un risque |
| [GrepLeaks](https://github.com/grepleaks/grepleaks) | Séparation méthode/outillage, état persistant et observabilité | Catalogue massif, dépendances et conditions de réutilisation prises pour acquises |
| [LoganSec](https://www.logansec.com/about/) | Documentation de la démarche, des apprentissages et des limites | Techniques actives transposées à la collecte OSINT sans périmètre autorisé |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Déduplication et cycle de vie des résultats | Modèle de vulnérabilités imposé à toutes les entités OSINT |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Protocole d'évaluation et reproductibilité | Dépendance obligatoire à un LLM ou benchmarks transposés sans mesure |

Les idées proposées sont des pistes d'étude, sans reprise de code, de skill ou
d'asset de ces projets. Toute future réutilisation devra identifier le fichier,
le commit, sa licence et les notices applicables, puis documenter la provenance.

ClaudeRed : référence à identifier et vérifier avant ajout à la sélection.
