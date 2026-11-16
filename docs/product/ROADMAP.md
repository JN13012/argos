# Argos — Roadmap de référence

Mise à jour : 16 novembre 2026. Cette page porte les priorités actives et les
critères de livraison. Les plans spécialisés détaillent les lots ; ils ne
constituent pas une preuve d’implémentation.

## Cible produit

Argos doit pouvoir **mener une mission de cybersécurité en autonomie complète** :
planifier, choisir et exécuter les capacités autorisées, interpréter les
observations, adapter son parcours, vérifier ses constats et produire le rapport.
Un mode assisté reste utile pour les experts, sans limiter la cible à un copilote.

**Première valeur commerciale : le pentest web et API autonome**, authentifié
et multi-rôles, depuis le CLI, avec preuves, rapport et recontrôle. Le
[plan web W0–W9](WEB_PENTEST_PLAN.md) organise les livraisons et la qualification.
Le niveau senior est une cible à mesurer, pas une capacité actuelle annoncée.
OSINT élargi, AD, cloud, DEFEND/GRC et sécurité des LLM passent après ce parcours.

L’autorisation initiale fixe les cibles, les actions permises, la période et les
budgets. Les étapes déjà autorisées doivent pouvoir s’enchaîner sans validation
humaine répétitive. Une extension du périmètre ou des permissions exige une
nouvelle autorisation ; révocation, dépassement de budget et conditions d’arrêt
s’imposent au moteur indépendamment du modèle.

## État constaté

| Capacité | État au 16 novembre 2026 |
| --- | --- |
| OSINT SIRENE | Implémenté en CLI : découverte bornée, SQLite, provenance et rapports |
| ATTACK P1 | Implémenté en bibliothèque : missions signées, Nmap, preuves et reconnaissance en deux phases ; qualification de production incomplète |
| API | Intégrée au frontend uniquement pour `GET /api/v1/health` |
| Interface métier | Absente de l’application montée ; composants historiques conservés |
| Agent / LLM | Conçu, aucun moteur connecté ; A1–A4 proposés sur `origin/feat/agent-foundation` |
| Enum2Root / PromptLab | Références étudiées, pas d’intégration fonctionnelle complète |
| DEFEND / GRC | Direction future, aucune capacité métier opérationnelle |

## Lots et critères de sortie

| Lot | Statut | Livrable et critère de sortie |
| --- | --- | --- |
| P0 — Fiabilisation | Validé localement ; exécution distante de CI à confirmer après publication | Typage et lint globaux propres, installation verrouillée reproductible, tests Python 3.12/3.14, frontend et navigateur ; documents cohérents. Voir le [bilan P0](FIABILISATION_P0.md). |
| P1 — Exécution durable et isolée | P1.1–P1.4 livrés et qualifiés localement ; P1.5 à faire | Réseau rootless à refus par défaut, quotas, nettoyage et profil lié aux preuves. Suite : Nmap réel en labo autorisé et revue ciblée. Voir le [découpage P1](EXECUTION_P1.md) et la [qualification réseau](MISSION_NETWORK.md). |
| W0–W9 — Pentest web autonome | Planifié, priorité commerciale | W0 clôt P1.5 ; W1–W6 construisent mandat, labo, HTTP, CLI, navigateur, tests et restitution ; W7 ajoute l'agent ; W8 mesure et W9 prépare les pilotes. Voir le [plan détaillé](WEB_PENTEST_PLAN.md). |
| P2 — API et interface métier | Après validation du parcours CLI web | Identités et droits par mission ; API et UI mission → autorisation → job → preuves → rapport → recontrôle. Réutiliser les services CLI ; accès croisés refusés. Requis avant le libre-service multi-utilisateur. |
| A1–A3 — Connaissance, outils et état | Conçus | Catalogue original versionné, prérequis et preuves explicites, registre de capacités typées, état de mission persistant. Recommandations bloquées expliquées, provenance conservée, reprise testée. |
| A4 — Mission autonome V0 | À construire, dépend de P1 et A1–A3 | Boucle objectif → plan → action → observation → vérification → replanification → rapport ; modèle interchangeable, budgets et arrêts. Une mission de référence se termine sans intervention entre les actions préautorisées ; chaque conclusion renvoie à ses preuves. |
| A5 — Évaluation de l’autonomie | À construire avec A4 | Comparaison aux workflows déterministes et manuels : réussite de mission, précision, omissions, coût, temps et interventions. Tests d’injection indirecte, panne et reprise ; seuils fixés avant mesure. |
| LLM Security | À construire | Cibles, campagnes, tests versionnés, connecteurs, chaînes bornées, oracles et revue. Parité sur un périmètre explicite avec le besoin couvert par PromptLab ; aucun succès déclaré sur un simple HTTP 200. |
| Bêta professionnelle | À qualifier | Restauration des sauvegardes, migrations, observabilité, rétention, gestion de secrets, revue indépendante et pilote. Exigences de disponibilité et support définies puis mesurées. |

A1 peut avancer indépendamment des écrans ; l’exposition d’actions actives
dépend de P1. La délégation entre agents vient après une mission autonome V0
mesurée ; elle doit apporter un bénéfice vérifié.

Pour la première offre, A1–A3 sont concrétisés par W1–W6, A4 par W7 et A5 par
le protocole défini dès W1 puis exécuté en W8. Ces identifiants désignent des
responsabilités existantes, pas deux programmes de développement concurrents.
Ordre actif : **W0/P1.5 → W1 → W2/W3 → W4/W5/W6 → W7 → W8 → W9** ;
les dépendances précises et les travaux préparatoires figurent dans le plan.

## Sources et réutilisation

Une brique publique peut être adoptée, adaptée ou simplement servir de référence.
Le choix Hermes / moteur propre reste ouvert jusqu’à un essai comparatif. Voir
le [dossier de sélection](REFERENCES.md) : agent, workflow, méthodologie,
ATT&CK, CVE/KEV, reconnaissance, OSINT et gestion des constats.

Toute adoption documente version ou commit, licence applicable, dépendances,
frontière d’exécution, provenance des résultats et tests d’acceptation. Le modèle
propose les actions ; le runtime Argos possède les permissions et les preuves.

## Trajectoire OSINT conservée

La fondation existante reste réutilisable sans agent. Les extensions prévues
sont la résolution des sites, l’enrichissement et les analyses d’opportunité,
avec couverture et limites explicites. Elles n’imposent plus à elles seules
l’ordre de livraison de toute la plateforme.
