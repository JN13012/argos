# W2.3 — Runtime HTTP persistant

Le runtime HTTP interne est implémenté : demandes, tickets, quotas, échanges
expurgés, couverture et audit persistent dans la base des missions. Il réutilise
le [transport isolé W2.2](WEB_HTTP_TRANSPORT.md). Le [CLI et la découverte W3.1](WEB_CLI_DISCOVERY.md)
le consomment désormais, ainsi que [la vérification et le recontrôle W3.2](WEB_OPEN_REDIRECT.md).
La politique générale n'autorise toujours aucun appel HTTP générique ; seul ce
chemin interne possède le cycle de tickets et de revalidation décrit ici.

## Utilisation interne

`WebRuntime` reçoit le chemin d'une base de missions et le vérificateur public
Ed25519. Sa construction exige un répertoire privé appartenant à l'utilisateur
(mode 0700), un fichier régulier sans lien symbolique, puis applique 0600 à la
base. Le verrou POSIX sur son inode est partagé avec le runtime Nmap : un seul
propriétaire d'exécution par base. Les constructeurs ne lancent aucune requête.

- `submit(WebRequest)` vérifie la configuration v2 signée, persiste une demande
  `pending` et renvoie son identifiant. Aucune résolution ou exécution implicite.
- `run(id)` réalise explicitement une tentative possédée par ce runtime. Plusieurs
  threads peuvent appeler cette méthode ; les réservations SQLite bornent le
  travail de toute la mission. Il n'existe pas de file de threads illimitée.
- `run_chain(id)` suit les redirections incluses, avec une nouvelle demande,
  résolution et réservation par saut. Le résultat donne les échanges persistés
  et une raison d'arrêt. Aucun retry automatique après une erreur.
- `get(id)` et `evidence(id)` vérifient les liaisons persistées avant de retourner
  état et preuve structurée. Les URL originales, profils et résolutions privés
  ne sont pas présents dans ces vues ordinaires.
- `cancel(id)` interrompt une tentative ou annule une demande en attente.
  `close()` cesse l'admission, annule les tentatives en cours, attend leur fin
  et l'audit des chaînes, puis libère le verrou. Les autres demandes `pending`
  restent persistées, sans programmation automatique.
- `resume(id)` réclame explicitement une demande abandonnée encore `pending`,
  après revalidation ; elle ne l'exécute pas. Une tentative ayant déjà réservé
  son ticket ne peut jamais être reprise par cette méthode.

Ces API sont internes et locales, pas un contrôle d'accès multi-utilisateur.
Les remplacements de worker/résolveur dans les tests sont des adaptateurs de
confiance ; aucun champ agent ne peut choisir du code, un résolveur, une IP,
un bundle CA ou un profil d'isolation. Le worker de production reste celui de
W2.2, sans repli vers le réseau du processus hôte.

## Ordre d'une tentative

1. Relire le grant exact et calculer le budget depuis les enregistrements
   persistés, avec contrôle d'intégrité. La durée commence à la première
   utilisation de la mission par ce runtime ; les attentes et redémarrages
   ne remettent pas ce compteur à zéro.
2. Réserver atomiquement un ticket et la capacité maximale de preuve, avant
   DNS. La signature est revalidée dans cette transaction. La tentative consomme
   définitivement une unité du budget de requêtes, même si DNS ou TCP échoue.
3. Résoudre sous supervision et revalider toute la réponse DNS avec W2.1.
   Une adresse interdite suffit à refuser l'ensemble. Aucun fallback IP caché.
4. Déduire DNS et attente de la deadline de cette tentative. Moins d'une seconde
   disponible ne permet pas de lancer un worker dont la limite murale minimale
   est une seconde : échec explicite, sans prolonger la deadline.
5. Revalider mission et ticket dans la transaction qui marque le lancement.
   Persister résolution et profil complet : requête canonique, origine logique,
   timeout effectif, destination, quotas, code, CA et helpers liés par empreintes.
   Le worker recalcule son profil et le compare avant tout lancement isolé.
6. Contrôler activité, révocation, annulation et deadline pendant DNS et le
   worker. Une fois la réponse obtenue, vérifier encore le profil du worker.
7. Construire la preuve par liste d'observations autorisées, puis commettre
   ensemble état terminal, preuve, couverture, octets consommés, pause éventuelle
   de l'origine et événement d'audit. Revalider la mission dans cette même
   transaction SQLite ; une révocation déjà commise interdit un succès.

Le partage de connexion en lecture de `MissionStore` permet cette revalidation
sans ouvrir une transaction concurrente ou changer les signatures historiques.
Une révocation arrivant après le commit ne réécrit pas un échange historique.
Une requête déjà transmise peut avoir eu un effet distant ; un arrêt local ne
prouve pas l'absence d'effet serveur.

## Quotas et pauses

Les plafonds signés s'appliquent à toute la mission : tentatives, concurrence,
durée, débit et preuves. La concurrence globale borne aussi chaque origine ;
changer d'origine ou d'IP ne multiplie jamais le budget. Une origine ne possède
pas de plafond supplémentaire réglable dans cette version.

L'admission des tickets et les lancements sont espacés globalement et par
origine selon `requests_per_second`. Il s'agit d'un débit de lancement de
workers, pas d'une garantie de rythme exact des paquets après le démarrage des
namespaces. Les demandes déjà soumises attendent un créneau sans DNS anticipé.
La file persistée est bornée à 128 demandes `pending` par défaut, au plus 1000
par configuration administrateur. Les refus d'admission conservent leurs codes
sans URL ; seuls les 1000 derniers sont gardés dans cette table dédiée.

Le ticket réserve le plafond de sortie du worker avant DNS. Après commit,
seuls les octets JSON réellement conservés pour la preuve, le profil et la
résolution occupent ce budget ; la marge est libérée atomiquement. Les preuves
d'annulation sans ticket comptent aussi. Ce quota n'est pas la taille physique
du fichier SQLite : demandes privées, index, journal et événements de contrôle
ont leur propre coût. Aucun corps brut de réponse n'est archivé ici.

Une réponse 429 ou 503 n'est pas rejouée. `Retry-After` accepte secondes ou date
HTTP ; sans valeur unique valide, la pause vaut cinq secondes. Une attente
valide supérieure au plafond signé suspend l'origine, sans reprise anticipée
au bout de ce plafond. La suspension reste après redémarrage ; une autre IP
ne la contourne pas. Une autre origine incluse garde ses propres possibilités,
toujours sous les limites globales.

L'horloge monotone protège les deadlines du processus vivant. La dernière heure
observée persiste ; après redémarrage, un recul de plus d'une seconde de l'heure
murale bloque les nouvelles réservations jusqu'au rattrapage. Un recul faible
est borné par le maximum déjà observé. Cela ne remplace pas une horloge système
fiable ni une mesure externe du temps écoulé pendant une panne.

## Redirections

Seuls 301, 302, 303, 307 et 308 sont suivis en découverte. Chaque saut est soumis
à la politique complète avant DNS. Maximum cinq sauts, ou la limite signée plus
basse ; cycles, Location multiples et destinations invalides arrêtent la chaîne.
HTTPS vers HTTP n'est pas suivi automatiquement. `http.check_redirect` ne suit
jamais Location, même si sa destination serait incluse.

La Location brute reste temporairement en mémoire pour choisir le saut suivant.
La preuve ordinaire indique sa présence ; la raison d'arrêt rejoint l'audit.
Une URL de marqueur placée dans une query n'est pas une cible réseau. Aucune
information d'authentification ou cookie n'est transférée, même entre deux
origines sur la même IP. Après un crash, les Locations ne sont pas récupérées
pour relancer une chaîne implicitement.

## Preuves et confidentialité

Tables HTTP versionnées distinctes des tables de scan Nmap : sessions,
origines, demandes, tickets, preuves, couverture, événements et refus.
La preuve `web-redaction-v1` contient identités, empreintes de configuration,
requête, résolution et profil, état, code stable, date, statut HTTP, complétude,
volume retenu et quelques observations : présence de Location, nombre de
Set-Cookie, présence d'un challenge d'authentification. La couverture est
`executed` pour un échange complet, `blocked` pour les autres issues, jamais
`verified` par le seul transport.

Ni corps, extrait de corps, cookie, valeur de header, chemin ni query originaux
ne sont copiés dans cette preuve. Les erreurs ne reprennent pas les exceptions
brutes. Cette approche évite de prétendre qu'une regex expurge tout contenu.
Le hash couvre la preuve expurgée, sans publier un hash du corps brut. L'extraction
d'observations propres à une capacité, notamment les nonces de redirection,
est ajoutée avec la capacité W3.2, sans exposition des Locations arbitraires.

La requête originale nécessaire à une reprise `pending`, le profil technique et
la résolution restent dans la zone privée de la base, en clair. Pas de chiffrement
au repos, isolation multi-tenant ou politique automatique de purge livrés ici.
La rétention de cette base reste une décision explicite de l'opérateur ; ne pas
la déplacer, renommer ou remplacer pendant qu'un runtime détient son verrou.

Les lectures vérifient requête, réservation, profil, résolution, reçu, couverture
et chaîne des événements associés. Une altération détectée ou un échec de
persistance arrête les nouvelles admissions et annule les autres tentatives.
Les empreintes locales détectent des incohérences ; elles ne constituent pas
une signature contre un administrateur capable de réécrire toute la base.

## Pannes et reprise

`reserved` ou `running` au redémarrage devient `interrupted`, avec preuve et
audit atomiques, sans DNS ni nouvelle exécution. Le ticket reste consommé.
La preuve distingue `not_started` d'un envoi `possible` ; cette dernière valeur
reste conservatrice dès que le lancement a été enregistré, même si une panne
d'isolation a pu survenir avant la connexion effective.

Une faute d'écriture annule la transaction entière : aucun succès, reçu isolé,
quota libéré ou événement terminal orphelin. Le runtime reste fermé aux nouvelles
actions. Un nouveau propriétaire réconcilie l'issue incertaine sans réutiliser
un PID enregistré et sans renvoi, même pour GET. Seules les demandes restées
`pending` sans réservation peuvent être réclamées explicitement.
Un refus avant réservation laisse cette demande non envoyée en `pending`, avec
son refus audité ; il ne fabrique pas d'échange ou de vulnérabilité.

## Validation et suite

49 nouveaux tests couvrent notamment saturation, quotas persistants, débit,
concurrence, pauses par origine, refus avant DNS, DNS mixte, deadlines, scopes,
redirections, expurgation, profils modifiés, altérations de stockage, rollback,
révocation, arrêt et récupération après un processus réellement tué.
**À la livraison W2.3, 651 tests passent sous Python 3.12 et 3.14**, dont 612 tests réguliers et
39 tests hôte activés explicitement. Ruff, formatage et Pyright passent aussi ;
le contrôle hors ligne du corpus W1.2 reste valide.

Quatre essais hôte utilisent le worker HTTP isolé réel avec des serveurs locaux :
échange et preuve, redirection externe refusée, révocation en cours et panne de
commit après réception sans répétition. Les dépendances temporaires et commandes
hôte sont celles du [rapport W2.2](WEB_HTTP_TRANSPORT.md#validation).

**W3.1 livré** : voir le [bilan CLI/découverte](WEB_CLI_DISCOVERY.md). Il ajoute
capture déterministe bornée, frontière persistante, lecture seule des sorties,
stop et reprise, avec preuve/capture/nouveaux liens dans la même transaction.

[W3.2 est livré](WEB_OPEN_REDIRECT.md) : route et paramètre découverts, référence,
deux marqueurs jamais contactés, constat contrôlé par oracle, témoin corrigé
et recontrôle. Suite : W4.1, navigateur anonyme confiné. Aucun benchmark W1.2
ou client réel n'est évalué par ces lots ; l'agent et les autres familles restent au plan.
