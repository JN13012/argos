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
