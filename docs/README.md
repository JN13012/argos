# Documentation d’Argos

Argos vise le pentest web/API autonome en situation client, d’abord depuis le
CLI et en boîte noire externe. Cet index sépare le produit visé, les capacités
réelles, les travaux à réaliser et les documents historiques.

## Entrées de référence

| Question | Document responsable |
| --- | --- |
| Comment contribuer dans ce dépôt ? | [AGENTS.md](../AGENTS.md) : consignes de développement, validations et commits |
| Où en est-on et que développe-t-on ensuite ? | [Roadmap](product/ROADMAP.md) : statuts, ordre, jalons et prochaine tâche |
| Que doit couvrir la première offre web ? | [Scope](product/SCOPE.md) : périmètre et limites produit |
| Comment passer du socle au pentest autonome ? | [Plan web](product/WEB_PENTEST_PLAN.md) : démarche, dépendances et qualification |
| Quels tests web faut-il construire ? | [Catalogue de capacités](product/WEB_CAPABILITIES.md) : familles, preuves et critères de livraison |
| Comment produire et relire le premier rapport client ? | [Export W6](product/WEB_CLIENT_REPORT.md), [guide](development/WEB_REPORT_GUIDE.md) et [exemple](development/examples/web-client-report.md) |
| Quel lot vient d’être livré et quelle est la suite ? | [W4.3](product/WEB_INTERACTIONS.md) : requêtes structurées W4.3a et redirections navigateur W4.3b ; actions/sessions W4.3c à détailler |
| Comment est construit le logiciel actuel ? | [Architecture](architecture/ARCHITECTURE.md) |
| Comment fonctionnera l’agent autonome ? | [Architecture agent cible](architecture/AGENTIC_CORE.md), conception distincte de l’implémentation |
| Pourquoi une décision d’architecture ? | [Monolithe](architecture/adr/0001-modular-monolith.md) et [interception navigateur](architecture/adr/0002-browser-redirect-interception.md) |
| Quelles briques publiques ont été étudiées ? | [Références](product/REFERENCES.md), candidatures et conditions d’adoption |
| Quelle vision et quel usage ? | [Vision](product/VISION.md) et [cadre](product/CADRE.md) |

La roadmap est le point de mise à jour des statuts. Les documents de lot
conservent leurs contrats, bilan et limites. Le README racine présente le
projet ; le scope n’est pas un second journal d’avancement. Si le code et un
statut divergent, examiner la divergence : une régression du code ne justifie
pas de modifier silencieusement l’objectif ou les critères d’acceptation.

## Références techniques applicables

Les lots livrés restent consultables : ils décrivent les comportements dont
les suivants dépendent. « Livré » ne signifie ni obsolète ni qualification
universelle sur des applications client.

| Domaine | Documents |
| --- | --- |
| Configuration web | [W1 boîte noire](product/WEB_W1_BLACKBOX.md), [configuration W1.1](product/WEB_CONFIG.md), exemples [HTTP v2](development/examples/web-mission-v2.json), [navigateur v3](development/examples/web-mission-v3.json), [interactions v4](development/examples/web-mission-v4.json) et [redirections v5](development/examples/web-mission-v5.json) |
| HTTP | [Spécification W1.3](product/WEB_HTTP_EXECUTION.md), [politique W2.1](product/WEB_HTTP_POLICY.md), [transport W2.2](product/WEB_HTTP_TRANSPORT.md), [runtime W2.3](product/WEB_HTTP_RUNTIME.md) |
| Découverte et premier test | [CLI W3.1](product/WEB_CLI_DISCOVERY.md), [redirection/recontrôle W3.2](product/WEB_OPEN_REDIRECT.md) |
| Qualification de la reconnaissance | [M2.7 multi-laboratoires](product/RECON_QUALIFICATION.md) et [consolidation M2.7.1](product/RECON_CONSOLIDATION.md) : comparaison de missions complètes, résultats et limites avant M3 |
| Revue de mission M3.1 | [Fondations, contexte et journal opérateur](product/M31_FOUNDATIONS.md) et [audit préalable](product/DECISION_ENGINE_AUDIT.md) |
| Analyste local M3.2 | [Fournisseur Ollama, contrat et qualification](product/M32_LOCAL_LLM_ANALYST.md) |
| Énumération contextuelle | [M2.6 Contextual Enumeration Engine](product/CONTEXTUAL_ENUMERATION.md) |
| Cartographie applicative | [M2.5 Application Mapping Engine](product/APPLICATION_MAPPING.md) |
| Identification technologique | [M2.4 Fingerprinting Engine](product/FINGERPRINTING.md) |
| Cartographie réseau bornée | [M2.3 Network Recon Engine](product/NETWORK_RECON.md) |
| Reconnaissance par outils | [Pipeline Nmap, Gobuster et ffuf](product/WEB_RECON.md) |
| Interactions | [W4.3](product/WEB_INTERACTIONS.md) : configuration, méthodes, corps/en-têtes et reprise |
| Navigateur | [Worker W4.1](product/WEB_BROWSER_WORKER.md), [contrats et intégration W4.2](product/WEB_BROWSER_RUNTIME.md) |
| Évaluation web | [Corpus et limites](../benchmarks/web/README.md), [manifest pour l’évaluateur](../benchmarks/web/manifest.json) ; données de correction séparées des entrées de l’agent évalué |
| Isolation | [Worker sans réseau](product/WORKER_ISOLATION.md), [réseau de mission](product/MISSION_NETWORK.md), [exécution P1](product/EXECUTION_P1.md) |
| Fondations Nmap | [MVP](product/PENTEST_MVP.md), [signature](product/PENTEST_P131_ED25519.md), [exécution](product/PENTEST_P132_EXECUTION.md), [preuves](product/PENTEST_P133_EVIDENCE.md), [reconnaissance adaptative](product/PENTEST_P134_ADAPTIVE.md), [limites ouvertes P1.5](product/PENTEST_P135_HARDENING.md) |
| OSINT existant | [SIRENE et principes](product/OSINT.md) |

Les versions et commandes historiques d’un lot sont son bilan daté. Utiliser
les fichiers de dépendances et le lot concerné pour préparer un nouvel essai ;
ne pas présenter un ancien nombre de tests comme une exécution du jour.

## Bilans et historique

- [Fiabilisation P0](product/FIABILISATION_P0.md), [revue P1.2](product/PENTEST_P12_REVIEW.md)
  et [audit du 16 novembre 2026](product/AUDIT_2026-11-16.md) : constats et preuves datés.
- [Proposition initiale d’architecture](architecture/README.md) : document
  historique explicitement remplacé par l’architecture actuelle.
- [Plan frontend](development/frontend/PLAN_FRONTEND.md), [revue visuelle](development/frontend/HOME_DESIGN_REVIEW_HISTORIQUE.md),
  [brief 3D](development/BRIEF_3D_MASCOTTES.md) et [assets 3D](development/frontend/BRIEF_ASSETS_3D.md) :
  travaux de présentation, distincts des capacités métier montées.
- [Présentation française](presentation/ARGOS-presentation-fr.pdf) et
  [présentation originale](presentation/ARGOS-presentation.pdf) : vision et support
  de présentation, sans valeur de preuve d’une capacité opérationnelle.

## Maintenir la documentation

1. Modifier le document responsable de l’information ; ajouter des liens depuis
   les autres pages plutôt que recopier des tableaux d’avancement.
2. Dans un lot : objectif observable, dépendances, tâches, critères, commandes,
   résultat des essais, limites et décision de clôture. Une préparation reste
   marquée « préparé, non implémenté ».
3. Décrire une décision significative dans un ADR ; la documentation de produit
   ne remplace pas les contrats et tests du code.
4. Conserver les documents livrés et leur provenance. Ne déplacer ou archiver
   un fichier qu’après correction de ses liens ; aucune suppression en masse.
5. Vérifier les liens locaux, blocs d’exemples et `git diff --check`. Aucun
   rapport client, secret ou résultat sensible ne rejoint cette documentation publique.
