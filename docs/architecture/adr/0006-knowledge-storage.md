# ADR 0006 — Un fichier SQLite par frontière documentaire

**Statut** — adopté pour les fondations M3.5.1.

**Décision.** Une base privée par collection ouverte, sous le répertoire de
l'UID effectif. Le fichier porte sa propre identité de portée et refuse une
ouverture sous une autre identité. Les originaux sont des BLOB dédupliqués par
SHA-256 à l'intérieur de cette base. Les versions et transitions de publication
sont transactionnelles. Les collections organisationnelles attendent un
contrat de partage vérifiable.

**Motif.** Une base unique aurait rendu une erreur de filtre susceptible
d'exposer un corpus et ses statistiques de classement. Des originaux dans
des fichiers séparés auraient exigé une coordination supplémentaire entre le
système de fichiers et SQLite lors d'un import interrompu. Les BLOB bornés
permettent de garder la provenance et les octets exacts dans la même
transaction.

**Conséquences.** Les identités de mission sont explicites, la séparation
de fichiers complète les permissions Unix et la déduplication cesse à la
frontière. Les bases sont sauvegardées par collection. Les opérateurs sous
un même UID partagent le même domaine de confiance. Le retrait logique
préserve les versions et originaux retenus pour inspection. Le débit des
imports et la taille de sauvegarde devront être mesurés si les bornes du
pilote changent. Voir la [spécification canonique](../../product/KNOWLEDGE_ENGINE_SPEC.md).
