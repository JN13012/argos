# ADR 0004 — Mémoire locale cloisonnée par UID et mission

Statut : adopté pour M3.4.

Le journal M3.3 garde les preuves et événements originaux. La mémoire est une
projection consultative reconstruisible, avec son propre cycle de focalisation
et de suppression logique. Nous utilisons SQLite stdlib, dans un répertoire
privé 700 et un fichier 600 par UID effectif / UUID de mission. Le contexte
ne permet jamais de parcourir plusieurs missions par défaut ou par wildcard.
Une identité applicative déclarative n'aurait aucune valeur d'authentification
sur ce CLI ; l'identité vient donc du système, sans paramètre utilisateur.
Les processus partageant le même compte Unix restent dans le même domaine
de confiance. Le serveur Web et les ACL multi-utilisateur ne sont pas implémentés.

Une chaîne versionnée d'événements mémorise captures, focalisation et tombstones,
avec empreinte de tête externe facultative pour détecter les restaurations.
Les projections sont rejouées à la lecture pour éviter un index dérivé non
vérifié. Les captures sont atomiques et idempotentes ; les doublons sont groupés
à la récupération sans fusionner les preuves ni effacer les contradictions.
Les suppressions sont logiques : elles ne promettent pas l'effacement physique
des anciennes données, journaux ou sauvegardes.

Un unique SQLite partagé avec toutes les revues faciliterait les migrations,
mais élargirait le risque d'une requête mal filtrée entre missions et utilisateurs.
Une base vectorielle ajouterait dépendances et coûts non justifiés par le corpus
actuel. Le compromis retenu privilégie le cloisonnement, la traçabilité et une
qualification mesurée avant toute indexation supplémentaire.
