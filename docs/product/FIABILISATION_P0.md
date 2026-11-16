# P0 — Fiabilisation du dépôt

Validation locale du 16 novembre 2026. Le [rapport initial](AUDIT_2026-11-16.md)
décrit l’état avant correction ; la [roadmap](ROADMAP.md) fixe la suite.

## Changements livrés

1. **Contrats Python et imports** — commit `8215460` : Pyright 1.1.414 ajouté
   aux dépendances de développement verrouillées ; configuration commune en mode
   basic sur tout le Python ; handlers compatibles avec le contrat FastAPI ;
   protocole du gestionnaire de reconnaissance ; résultats optionnels vérifiés
   dans les tests ; réexportations explicites du chemin OSINT historique.
2. **Qualité globale** — commit `9506c13` : Ruff et formatage étendus à tout
   le Python ; imports, lignes longues et enums OSINT corrigés. Les valeurs
   persistées des enums restent identiques. Sur les 35 fichiers de ce lot,
   32 gardent le même AST ; les trois autres contiennent les changements revus
   d’enums, de présentation des rapports et de mise en forme SQL.
3. **CI et lancement local** — commit `b873205` : contrôles sur les PR, `main`
   et `feat/**`, matrice Python 3.12/3.14, frontend et navigateur ; lancement de
   l’API par module Python avec dépendances verrouillées.
4. **Documents de référence** — vision, scope, architecture, roadmap et plans
   réconciliés ; anciens états marqués historiques ; sélection initiale de
   briques publiques avec commits, rôles, conditions et critères d’essai.

Les deux appels volontairement mal typés des tests négatifs (clé privée à la
place d’une clé publique, action inconnue) portent une exception locale et
nommée au contrôle statique. Ils continuent de vérifier le rejet à l’exécution.
Aucune règle globale de diagnostic n’est désactivée. Les deux tests API ajoutés
vérifient la conservation du statut et des en-têtes HTTP, ainsi que l’absence
des valeurs soumises dans les erreurs de validation.

## Réparation de l’environnement

L’editable et les scripts du venv pointaient vers un ancien dossier nommé
`Argos`. Réinstaller seulement le package corrigeait l’import mais laissait
encore les lanceurs `uvicorn` et `pytest` sur l’ancien chemin. La réparation
complète a été effectuée sans changer les versions verrouillées :

```sh
uv sync --locked --group dev --reinstall
```

Le package peut maintenant être chargé depuis les dossiers temporaires utilisés
par les tests CLI, sans ajouter de `PYTHONPATH`. Les lanceurs locaux pointent
vers `/home/cyber/work/argos/.venv/bin/python`. Ces fichiers locaux ne sont pas
versionnés. Le README décrit la réparation à refaire après déplacement d’un
checkout.

## Vérifications exécutées

| Vérification | Résultat |
| --- | --- |
| `uv lock --check`, y compris avec uv 0.11.31 prévu en CI | PASS : lock cohérent |
| `.venv/bin/ruff check .` | PASS : zéro diagnostic |
| `.venv/bin/ruff format --check .` | PASS : tous les fichiers au format attendu |
| `.venv/bin/pyright` | PASS : zéro erreur et zéro avertissement |
| Pyright 1.1.414 avec les stubs de Pylance 2026.4.1 | PASS : zéro diagnostic après corrections |
| `.venv/bin/python -m pytest -q -o faulthandler_timeout=10` | PASS : 188 tests avec Python 3.14.6, sans `PYTHONPATH` ajouté |
| Installation propre en environnement séparé sous `/tmp`, puis même suite avec Python 3.12.15 | PASS : 188 tests |
| `npm ci --no-audit --no-fund` dans `argos/frontend` | PASS : installation depuis le lock, sans modification de celui-ci |
| `npm run check` après cette installation | PASS : Prettier, ESLint, 22 tests, TypeScript et Vite |
| `npm run test:e2e` avec API locale et Chromium correspondant au lock | PASS : deux parcours, bureau et mobile émulé |
| Workflow YAML et `bash -n scripts/dev-api.sh` | PASS : configuration analysable et script valide |
| `git diff --check` | PASS |

Les tests ASGI ont été exécutés hors du bac à sable, qui provoquait un blocage
AnyIO lors de l’audit initial. Les processus Nmap de test sont synthétiques ;
aucun scan réel n’a été effectué.

Le premier essai navigateur a révélé le lanceur périmé ; le second a révélé
l’absence de la révision Chromium attendue. Ces causes ont été corrigées puis
les tests sont passés. Chromium a été installé sous `/tmp/argos-playwright-browsers`.
Pour reproduire avec ce cache local :

```sh
cd argos/frontend
PLAYWRIGHT_BROWSERS_PATH=/tmp/argos-playwright-browsers npx playwright install chromium
CI=1 PLAYWRIGHT_BROWSERS_PATH=/tmp/argos-playwright-browsers npm run test:e2e
```

La CI installe son propre Chromium et ses dépendances système. Elle utilise
Node.js 24.18.0 et uv 0.11.31 ; le lock a été vérifié avec cette version d’uv.
Les commandes Python utilisent directement l’environnement préparé pour chaque
version de la matrice, sans le resélectionner à partir de `.python-version`.

## Limites et suite

- La CI distante n’a pas été exécutée : les commits sont locaux, sans push.
  Les protections de branche et checks requis du dépôt distant ne sont pas
  modifiés ; ils devront référencer les nouveaux jobs lors de la publication.
- Le panneau Problems et le redémarrage de VS Code ne sont pas pilotés ici.
  Le contrôle reproductible, avec les stubs de Pylance, est propre ; une alerte
  d’éditeur persistante doit être comparée à ce résultat et à l’interpréteur.
- Les parcours Playwright couvrent l’accueil courant, pas une interface métier
  absente. Le mobile est émulé ; aucun appareil physique n’a été qualifié.
- Aucun audit exhaustif des dépendances ni qualification de production n’est
  revendiqué. P0 n’ajoute ni agent, ni outil de scan, ni intégration métier.
- À la clôture de P0, le compteur de jobs terminés, la reprise durable et les
  quotas système restaient ouverts. Le [suivi P1](EXECUTION_P1.md) décrit les
  corrections ultérieures ; P0 ne les revendique pas.

La cible produit confirmée est une mission autonome complète dans son mandat.
Le [dossier de références](REFERENCES.md) prépare le choix entre Hermes, un
moteur propre et des composants spécialisés ; aucune adoption n’est présumée.
