# M3.5-C.1 — Stockage et migration

Le stockage privé par défaut est `data/` à la racine du clone Argos. Lancé
depuis un autre répertoire, Argos utilise le même emplacement. Depuis une
installation Python hors clone, le défaut est `~/.local/share/argos/data`.
`ARGOS_DATA_HOME` accepte un chemin absolu, un chemin commençant par `~` ou
un chemin relatif au parent du répertoire de données par défaut.

```bash
/path/to/argos/scripts/argos data init
ARGOS_DATA_HOME="$HOME/argos-private" /path/to/argos/scripts/argos data init
```

L’initialisation crée des répertoires privés (0700), y compris à partir du
squelette d’un clone neuf. Si le répertoire personnalisé existe déjà, il doit
appartenir à l’utilisateur et être privé. Pour un stockage personnalisé situé
dans un clone, ajouter son emplacement à `.git/info/exclude` ou utiliser un
répertoire en dehors du dépôt.

| Espace | Destination |
| --- | --- |
| `ollama/` | Runtime et modèles locaux |
| `memory/` | Mémoires consultatives cloisonnées par UID et par mission |
| `missions/` | Bases et rapports persistants |
| `qualification/` | Résultats et archives de qualification privées |
| `backups/` | Sauvegardes et manifestes privés |
| `knowledge/`, `skills/`, `learning/`, `profiles/` | Réservés |

## Configuration des composants

| Composant | Valeur par défaut sous `ARGOS_DATA_HOME` | Configuration explicite |
| --- | --- | --- |
| Web et recon | `missions/missions.sqlite3` | `--db` |
| SIRENE | `missions/osint/argos.sqlite3` et `missions/osint/reports/` | `--db`, `--output-dir` |
| Commandes `review memory-*` | `memory/uid-UID/UUID.sqlite` | `--memory-root` prime sur `ARGOS_MEMORY_HOME` |
| Ollama | `ollama/runtime/bin/ollama`, `ollama/models/` | `ARGOS_LLM_HOME`, `OLLAMA_MODELS` et `ARGOS_OLLAMA_PORT` |
| Banc LLM | `qualification/benchmark/` | `--artifacts` et `--output` pour le JSONL |

Les chemins CLI explicites relatifs sont résolus depuis le répertoire courant.
La revue d'une archive continue d'exiger son chemin et, le cas échéant, celui
de son journal. L'API garde ses sources de résultats explicitement autorisées
via `ARGOS_RESULT_SOURCES`. Les fichiers d'environnement, les registres
d'outils, les listes administrées et les fixtures temporaires gardent leur
configuration. Examiner `ARGOS_RESULT_SOURCES` et les configurations privées
avant de désactiver un chemin historique.

```bash
export ARGOS_DATA_HOME="$HOME/argos-private"  # facultatif
/path/to/argos/scripts/argos data init
/path/to/argos/scripts/llm/ollama-local serve   # terminal dédié
/path/to/argos/scripts/llm/ollama-local list    # autre terminal, même environnement
/path/to/argos/scripts/argos review memory-info --mission-id UUID
```

Un clone neuf initialise le squelette. Pour Ollama, réutiliser une installation
locale en copiant `runtime/` et `models/` ou en définissant `ARGOS_LLM_HOME`.
Si un lanceur indépendant est déjà installé dans le PATH, conserver une copie
de ce fichier puis le faire pointer vers `scripts/llm/ollama-local` pour qu'il
emploie le même résolveur.

## Migration et restauration

| Origine | Copie sous `data/` |
| --- | --- |
| `~/.local/share/argos/ollama/{runtime,models}` | `ollama/{runtime,models}` |
| `~/.local/share/argos/memory` | `memory/` si une mémoire d'exploitation existe |
| `~/.local/share/argos/qualification/{m321-original,m33,m34}` | `qualification/{m321-original,m33,m34}` |
| `.argos/qualifications`, `.argos/m32-qualification` | `qualification/recon`, `qualification/m32` |
| `.argos/osint/argos.sqlite3`, `outputs/` | `missions/osint/argos.sqlite3`, `missions/osint/reports/` |
| `.argos/web/missions.sqlite3` | `missions/missions.sqlite3` si une base existe |

Les mémoires de qualification restent avec leurs deux exécutions M3.4. Les
captures, journaux et manifestes conservent leurs références d'origine.
Certains chemins dans les traces M3.3/M3.4 pointent vers les archives M2.7.1,
et les scripts historiques M3.2.1 référencent l'ancienne installation Ollama.
Les chemins d'origine sont conservés pour ces références. Les archives Git
de l'opérateur et les arbres bruts de bancs (fixtures, rootfs, outils et traces
intermédiaires) restent à leur emplacement d'origine.

1. Arrêter les processus qui écrivent dans les sources et vérifier qu'aucune
   base SQLite à copier n'a de fichiers `-wal`, `-shm` ou `-journal` actifs.
   Inventorier chemins, tailles, propriétaires, modes, liens et références.
2. Exécuter `data init`, puis comparer avec `df -B1` l'espace libre à la somme
   des tailles à copier. Réserver un répertoire privé dans `backups/` pour le
   manifeste et les copies en attente.
3. Calculer un manifeste SHA-256 des fichiers sources, avec chemins relatifs.
   Copier chaque source dans la zone d'attente avec `rsync -aAX --numeric-ids`.
   Pour les répertoires, terminer les chemins source et destination par `/`.
   Conserver les liens internes et vérifier individuellement leurs cibles.
4. Comparer les empreintes de la copie et des sources, puis effectuer un
   `rsync -naAXi --delete --numeric-ids` entre la source et la zone d'attente
   pour vérifier l'arborescence et les attributs. Installer chaque copie
   vérifiée par renommage vers une destination absente, sur le même volume.
   Contrôler les lectures SQLite, les chaînes mémoire et `ollama-local list`.
5. En cas d'échec, conserver le manifeste et la copie en attente. Reprendre
   avec les originaux via `--db`, `--output-dir`, `ARGOS_MEMORY_HOME`
   ou `ARGOS_LLM_HOME`, et rétablir l'ancien lanceur autonome si nécessaire.
   Après des écritures sur le nouveau stockage, sauvegarder cet état avant
   de repointer les composants vers les anciens fichiers.

Les originaux restent en place après validation. Les manifestes d'exécution
sont privés sous `data/backups/m351-migration/`. Voir aussi
[l'ADR stockage](../architecture/adr/0005-local-data-home.md).

## Validation locale

Neuf sources ont été copiées (18,4 Go). Les SHA-256 de 729 fichiers
correspondent avant et après installation. Les modes, propriétaires,
attributs et liens des copies correspondent aux sources. Les 59 bases SQLite
passent `PRAGMA integrity_check`. Les six chaînes mémoire M3.4 ont été
vérifiées contre les têtes d'origine. Les trois revues M3.3 et leurs snapshots
M2.7.1 correspondent aux originaux. Aucune mémoire d'exploitation ni base web
implicite n'était présente dans les emplacements historiques inventoriés.

Le lanceur installé `argos-ollama` pointe vers le lanceur du clone. Sa version
antérieure est conservée dans `backups/m351-migration/argos-ollama.before`.
Sur un serveur Ollama temporaire en loopback, `list` a retourné
`qwen2.5:0.5b`, `qwen3:4b`, `qwen3:8b`, `gemma3:4b` et `deepseek-r1:7b`.
Aucun appel d'inférence ni téléchargement de modèle n'a été effectué.

- `.venv/bin/ruff check .`, `.venv/bin/ruff format --check .`,
  `.venv/bin/pyright` et `git diff --check` passent.
- `python -m pytest -q -o faulthandler_timeout=30` donne 1 270 réussites
  et 121 ignorés sous Python 3.12 et 3.14. Les essais hôte optionnels restent
  hors de cette validation régulière.
- Dans un clone neuf, `uv sync --offline --locked --no-dev` puis `scripts/argos
  data init` et l'initialisation d'une base de test depuis un autre répertoire
  passent avec la racine par défaut et une racine personnalisée. La mémoire
  est lisible avec les trois résolutions proposées. Le clone reste propre,
  et les distributions source et wheel excluent les données privées.
- `git ls-files -- data resources` montre les guides et les marqueurs prévus.
  Les copies réelles sont ignorées. Les fichiers suivis ont aussi été
  contrôlés pour les signatures SQLite, GGUF et de clés usuelles.
