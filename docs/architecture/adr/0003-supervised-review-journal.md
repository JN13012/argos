# ADR 0003 — Persistance de la revue supervisée dans le journal privé

Statut : adopté pour M3.3, 25 novembre 2026.

Le journal opérateur M3.1 possède déjà un stockage SQLite privé et une chaîne
d'intégrité. La revue doit figer ses entrées, garder les essais et survivre
aux interruptions sans modifier la mission ni ouvrir un chemin d'exécution.

Nous ajoutons deux tables, `review_events` et `review_head`, dans ce même fichier.
Une chaîne distincte relie snapshots, requêtes expurgées, configurations,
complétions, résultats et annotations. Les acceptations référencent une entrée
vérifiée de la chaîne des décisions humaines existante. Un checkpoint externe
reste nécessaire pour détecter une restauration cohérente de tout le fichier.

Une base supplémentaire aurait séparé les cycles de sauvegarde et compliqué
les liens entre revue et décision ; des JSON dispersés auraient exigé notre
propre verrouillage et protocole de reprise. Les transactions SQLite et la
comparaison de la dernière empreinte de revue suffisent ici. Aucun nouveau
framework, service ni datastore n'est introduit.

L'inférence n'occupe pas une transaction ouverte. Son état `analyzing` est
committé d'abord ; un processus tué laisse cet état consultable. L'opérateur
marque explicitement une tentative orpheline interrompue avant reprise. Une
acceptation écrit la décision puis le lien de revue : une interruption entre
les deux laisse une décision sans lien final, récupérable par nouvelle soumission
du **même** identifiant et contenu, sans duplication. Ce protocole n'est pas
une transaction atomique couvrant ces deux opérations. Une acceptation ne
modifie aucune permission de mission et n'est jamais une autorisation.
