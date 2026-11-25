# M3.1 — Audit préalable du Decision Engine

Audit du socle au commit `ccd95be`, branche `feat/m31-decision-engine`.
Les essais portent sur la relecture des missions enregistrées et sur les
contrats des composants existants. Le moteur M3.1 reste à l'état non implémenté.

## Composants et interfaces

L'[architecture agent](../architecture/AGENTIC_CORE.md) décrit une architecture
cible. Dans le dépôt courant, les fonctions de gestion d'état, de politique,
de preuve et d'inventaire sont réparties entre plusieurs composants.

| Composant examiné | Contrat vérifié dans le code | Interface manquante ou limite |
| --- | --- | --- |
| State Engine | [MissionStore](../../argos/backend/core/mission_store.py) conserve le mandat, l'état et la révocation. [WebStore](../../argos/backend/attack/web/store.py) conserve les transactions et compteurs HTTP. [ReconStore](../../argos/backend/attack/recon/store.py) conserve les projections par exécution. | Les lectures ont des identifiants et fenêtres distincts. Le dépôt ne fournit pas d'instantané vérifié commun à tous les magasins. `WebStore.usage` est lié au contexte temporel du runtime et ouvre une transaction `BEGIN IMMEDIATE`. |
| Policy Engine | [WebPolicy](../../argos/backend/attack/web/policy.py) relit le mandat et la configuration signée. [AuthorizedNmapRunner](../../argos/backend/attack/pentest/authorized_execution.py) vérifie le mandat et passe par la [politique réseau de mission](../../argos/backend/core/policy.py). | Les compteurs HTTP et les plafonds opératoires Nmap mesurent des grandeurs différentes. Le solde observé d'un budget reste une mesure historique et ne vaut aucune autorisation. |
| Evidence Engine | [EvidenceStore](../../argos/backend/attack/pentest/evidence_store.py) vérifie les reçus Nmap. Le [vérificateur HTTP](../../argos/backend/attack/web/evidence_index.py) contrôle la cohérence avec le rapport issu de la base privée. | Les reçus sont spécifiques à leur transport. Les empreintes vérifient l'intégrité et les liaisons contrôlées par chaque lecteur. Une réécriture complète de la base et de ses sources peut échapper à ces contrôles. |
| Journal existant | [DecisionAudit](../../argos/backend/core/decision_audit.py) archive les admissions et refus de politique avec mission, IP, action, motif et horodatage. | Ce journal ne porte ni les sources de raisonnement ni la version de règles d'une décision consultative. Il n'existe pas d'archive M3.1. |
| Tool Registry | [ToolRegistry](../../argos/backend/core/tool_registry.py) inventorie les installations administrateur et contrôle les identités des binaires et ressources épinglés. | Il n'expose pas une vue uniforme des sorties métier, dépendances et coûts, notamment pour les projections passives. Une installation enregistrée ne prouve ni sa disponibilité au moment du run ni l'autorisation de l'utiliser. |
| [Reconnaissance réseau](NETWORK_RECON.md) | [`network_report`](../../argos/backend/attack/recon/network.py) vérifie les liaisons entre inventaire, jobs, résultats et reçus. La couverture distingue les couples demandés, admis, observés et non résolus. | Un couple non résolu reste inconnu. Le quota local d'un run ne s'additionne pas aux tickets HTTP. |
| [Fingerprinting](FINGERPRINTING.md) | [`fingerprint_report`](../../argos/backend/attack/recon/fingerprint.py) recalcule les identifications et leurs références selon la version archivée. | Une technologie ou une version inconnue ou contradictoire le reste à la relecture. |
| [Cartographie](APPLICATION_MAPPING.md) | [`application_report` et `query_application`](../../argos/backend/attack/recon/application_mapping.py) revalident le graphe, les assertions et les sources sélectionnées. | Les références déclarées, par exemple OpenAPI, restent distinctes des observations. Une sélection bornée laisse une couverture partielle. |
| [Énumération contextuelle](CONTEXTUAL_ENUMERATION.md) | [`plan_report`](../../argos/backend/attack/recon/context_plan.py) vérifie le plan historique. [`context_report`](../../argos/backend/attack/recon/context_execution.py) vérifie sa liaison au run et la couverture issue des reçus. | Les états `examined`, `not_examined`, `unknown` et `interrupted` décrivent la couverture d'un plan donné. Ils ne portent aucun jugement exhaustif sur la mission. |

## Vérifications hors ligne

Trois bases privées de [M2.7.1](RECON_CONSOLIDATION.md), issues de crAPI, DVWA
et Juice Shop, ont été ouvertes en lecture seule et copiées via l'API
`sqlite3.Connection.backup` dans des répertoires temporaires. La relecture a
utilisé exclusivement les cinq fonctions de rapport ci-dessus. Chaque base
contient six projections, dont deux cartes. Les 18 projections ont été lues
deux fois sous chacun des deux interpréteurs. Les empreintes des projections
en JSON canonique triées par identifiant coïncident sous Python 3.12.15 et
3.14.6.

| Archive M2.7.1 | Règles de fingerprinting relues | Tickets HTTP / admissions / plafond effectif du run contextuel | Candidats examinés / requêtes candidates dupliquées |
| --- | --- | --- | --- |
| crAPI contextuel r1 | `argos-fingerprint-v2` | 34 / 34 / 146 | 32 / 0 |
| DVWA contextuel r1 | `argos-fingerprint-v2` | 34 / 34 / 147 | 32 / 0 |
| Juice Shop contextuel r1 | `argos-fingerprint-v1` | 34 / 34 / 126 | 32 / 0 |

Les trois runs enregistrent `explicit_plan_completed`. Ils se terminent avec
un reliquat. Ce motif décrit la fin du plan archivé et la couverture reste
partielle. Ces trois archives couvrent la fin normale. Les cas d'interruption,
de reprise hors ligne et de budget insuffisant sont exercés par des fixtures.

Pour reproduire la relecture à partir d'une copie SQLite, relever les
identifiants de `recon_runs` par type, puis utiliser `python -m argos recon`
avec `--db COPIE` sur chacune des commandes de lecture `network-report`,
`fingerprint-report`, `map-report`, `context-plan-report` et `context-report`.
Fournir `--run-id` pour chaque projection et `--plan-id` pour le plan
contextuel. Comparer les sorties JSON sur deux lectures et entre versions
Python. Les bases et les sorties détaillées restent privées.

### Fixtures synthétiques

Les tests ci-dessous portent sur la cohérence des projections, les
contradictions conservées, les preuves altérées rejetées, les plafonds de
requêtes, les refus et les arrêts. Les fixtures contextuelles injectent le
résolveur, l'adaptateur et le worker HTTP, sans trafic vers une cible.

```bash
python -m pytest -q -o faulthandler_timeout=15 \
  tests/test_decision_audit.py tests/test_evidence_store.py \
  tests/test_fingerprinting.py tests/test_fingerprint_consolidation.py \
  tests/test_application_mapping.py tests/test_web_http_policy.py \
  tests/test_tool_registry.py::test_doctor_never_invokes_tools_or_targets \
  -k 'not pinned_endpoint and not pinned_bindings'
python -m pytest -q -o faulthandler_timeout=15 \
  tests/test_context_plan.py tests/test_context_execution.py
```

Résultats sous chacun des deux interpréteurs : 144 tests réussis et 3
désélectionnés sur la première commande, 17 tests réussis sur la seconde.
La sélection ne couvre pas la suite régulière complète ni les essais hôte.
Ces résultats qualifient les interfaces existantes dans ce périmètre. Ils ne
mesurent aucune décision ou priorité M3.1. Aucun nouveau scan, aucune
exploitation et aucun appel à un modèle ne font partie de l'audit.
