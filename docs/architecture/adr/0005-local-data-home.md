# ADR 0005 — Racine des données locales

**Décision.** Les données persistantes gérées par Argos utilisent `data/` à
la racine du clone ou l'emplacement `ARGOS_DATA_HOME`. Le CLI et le lanceur
Ollama partagent le résolveur. Les chemins explicites continuent de primer.
`resources/` est réservé aux futurs contenus initiaux redistribuables.

**Contexte.** Les valeurs implicites pointaient vers le répertoire courant ou
plusieurs emplacements sous le répertoire personnel. Le premier choix
produisait des bases différentes selon le répertoire de lancement. Une racine
XDG unique aurait résolu ce problème mais aurait demandé une configuration
supplémentaire pour identifier et déplacer les données de chaque clone. Le
placement dans le clone facilite cette identification et l'export de la racine
reste disponible pour le stockage partagé ou hors dépôt.

**Conséquences.** Git versionne un squelette et ignore les contenus privés. Le
répertoire est accessible uniquement au propriétaire. Les archives portant
des références historiques sont copiées et vérifiées avec leurs chemins
d'origine préservés. Voir le [lot M3.5-C.1](../../product/M351_DATA_ARCHITECTURE.md)
pour les priorités, la migration et la restauration.
