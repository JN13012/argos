# ADR 0006 — Un fichier SQLite par frontière documentaire

**Statut** — adopté en M3.5.1 et appliqué aux index M3.5.3 et M3.5.4.

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


Les index SQL et FTS5 restent dans le fichier de la collection. L'index
FTS5 référence une projection interne des fragments publiés. Les mises à
jour explicites dans la transaction de publication permettent de garder les
déclencheurs de l'application indépendants des tables virtuelles et de
conserver `trusted_schema=OFF`. Le classement n'utilise que les statistiques
de cette base, et la vérification compare la projection au corpus publié.

Les vecteurs Float32 et leur cache restent dans cette même base. L'espace
inclut le digest du modèle, sa version de prétraitement, sa dimension et
son runtime. Une clé étrangère fait disparaître chaque association
courante au retrait du fragment SQL dans la transaction de publication.
Les lots d'embeddings sont calculés hors transaction puis validés à
l'écriture. La recherche dense attend une couverture complète de
l'espace demandé et lit ses vecteurs par blocs.

M3.5.4.1 conserve SQLite comme source de vérité et dérive une vue NumPy
en mémoire. La révision et la marque de validation sont lues dans la
même transaction SQLite que les citations. La révision reflète les
changements de membres et la marque force la revalidation des vecteurs
dès qu'une donnée d'intégrité change. Le stockage privé reste le seul
support durable du moteur.

## Maintenance et publications révisées

SQLite v6 mémorise les périmètres de maintenance, le dernier contrôle
des manifestes et les publications passées. Une transaction applique le
plan validé, les retraits, les projections et les liens d’index. Le
fournisseur de fichiers reste séparé du stockage. Une vue dense dépend
uniquement de la génération SQLite et de ses membres courants.

Le rafraîchissement vectoriel synchrone est optionnel et borné. Il évite
de commettre une publication dont le calcul explicitement demandé a
échoué, au prix d’un verrou d’écriture maintenu pendant le lot. La
construction asynchrone existante reste le parcours des gros volumes.
Les mesures et limites figurent dans le
[bilan M3.5.7](../../product/M357_KNOWLEDGE_MAINTENANCE.md).
