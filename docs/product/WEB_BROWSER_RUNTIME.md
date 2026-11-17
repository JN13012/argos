# W4.2 — Navigation de mission et découverte SPA/API

Statut : **préparé, non implémenté**. Dépendances livrées :
[runtime HTTP W2.3](WEB_HTTP_RUNTIME.md), [CLI W3.1](WEB_CLI_DISCOVERY.md),
[oracle W3.2](WEB_OPEN_REDIRECT.md), [worker navigateur W4.1](WEB_BROWSER_WORKER.md).

## Résultat attendu

Depuis une mission démarrée avec une URL seule, explorer les pages éligibles
avec le navigateur isolé, observer leurs scripts et appels API, et conserver
les liens DOM et la provenance de chaque requête dans les résultats de mission.
La première démonstration doit trouver un lien absent du HTML initial, produit
par un script qui consulte une API, puis permettre sa consultation dans le rapport.

Cette tranche fournit une découverte anonyme supplémentaire. Elle ne livre
ni un agent LLM, ni de nouvelles familles de vulnérabilités, ni un pentest
complet. Une API observée n'est pas une API testée ou une vulnérabilité.

## Écart concret dans le code actuel

| Point existant | Travail nécessaire |
| --- | --- |
| La configuration v2 et `HTTP_CAPABILITIES` acceptent deux capacités HTTP | Ajouter une configuration v3 et une capacité navigateur distincte ; conserver les contrats de requêtes HTTP fermés |
| `BrowserWorker.navigate` appelle un médiateur de confiance, avec réponses en mémoire dans les essais | Construire un médiateur utilisant exclusivement le runtime HTTP signé |
| `WebRuntime.run` retourne un snapshot et conserve les corps uniquement pendant l'exécution | Ajouter une remise privée et bornée de la réponse après validation du commit HTTP |
| `WebStore.finish` termine reçu, couverture, audit et ticket dans une transaction | Y lier la ressource navigateur avant de permettre sa fourniture au rendu |
| La frontière HTML et les vérifications possèdent leurs propres liens d'arrêt/reprise | Ajouter les navigations et leurs ressources aux contrôles d'arrêt, d'intégrité et de récupération |
| `web status/report` lisent un snapshot sans exécuter d'action | Étendre ces vues avec la couverture navigateur et les API observées |

## Décisions de réalisation

1. **Configuration v3 explicite.** Capacité proposée `browser.discover`, avec
   `http.discover` nécessaire au relais. Les configurations v1/v2 restent
   inchangées : aucune migration silencieuse, modification de signature ou
   activation du navigateur par une ancienne mission. La séparation des types
   doit empêcher de soumettre `browser.discover` comme un `WebRequest` HTTP.
   Le chargement, la signature et la politique doivent reconnaître v3 ensemble.
2. **Même runtime et même propriétaire.** Garder `runtime.operation()` sur toute
   la navigation ; réutiliser le verrou de base existant. Ne jamais conserver
   une transaction SQLite ouverte pendant Chromium, DNS, le réseau ou une
   attente de débit. Le médiateur reste sur le thread propriétaire. Le slot
   navigateur est distinct des slots HTTP : une mission avec concurrence HTTP
   égale à un doit fonctionner, sans attente circulaire entre parent et enfant.
3. **Chaque sortie réseau correspond à un ticket HTTP.** Lier la navigation,
   l'identifiant de ressource et le ticket avant connexion. Reprendre les
   contrôles d'origine, chemins, effets, DNS, IP, Host/SNI, TLS, débit,
   Retry-After, expiration et révocation du runtime. Aucun socket Internet dans
   le navigateur ni client HTTP de remplacement dans le médiateur.
4. **Réponse remise seulement après commit réussi.** Le passage privé doit
   contenir identifiants, empreinte du reçu et réponse complète bornée. Il est
   interne, à usage unique, sans cache général et sans corps dans le snapshot
   public. Relire activité et deadline avant remise ; si l'écriture du reçu,
   la liaison ressource ou sa vérification échouent, rien n'est fourni au
   navigateur, le runtime devient indisponible et les autres actions s'arrêtent.
5. **Deux deadlines, sans prolongation.** La durée de navigation comprend
   démarrage, attente de débit, DNS et sous-requêtes. Chaque opération enfant
   utilise la plus petite deadline : mission, navigation, requête. Un HTTP
   imbriqué ne doit pas empêcher le nettoyage du navigateur après sa deadline.
   Le médiateur vérifie aussi l'arrêt de la navigation pendant les attentes.
6. **Conserver les restrictions W4.1 pour la première tranche.** GET/HEAD,
   une origine exacte par navigation, sans cookies transmis ni authentification,
   service workers/WebSockets bloqués. Les réponses 3xx restent refusées et
   signalées comme limites. Ne pas fournir discrètement une réponse finale
   sous l'URL initiale : cela fausserait URL visible et résolution des liens.
   Les redirections et sessions font l'objet de W4.3 avant une couverture plus
   large des applications réelles. Les origines découvertes ne s'ajoutent pas
   au scope ; les CDN absents du périmètre restent bloqués et visibles.
7. **Une observation n'est pas une conclusion de sécurité.** Conserver séparément
   ressource vue, échange exécuté, liens observés et tests de vulnérabilité.
   Le rendu peut être partiel même si des requêtes HTTP ont réussi.

## Budgets à signer

La section navigateur v3 devra valider des entiers bornés, refuser les champs
inconnus et exposer ses limites dans `web plan`. Valeurs de départ proposées
pour l'implémentation, sans changer le profil système qualifié en W4.1 :

| Budget | Valeur de départ / plafond de cette tranche |
| --- | --- |
| Navigations par mission | 10 / 10 |
| Navigations simultanées | 1 / 1 |
| Durée d'une navigation | 30 s / 30 s |
| Ressources d'une navigation | 64 / 64 |
| Corps d'une ressource | 512 Kio / 512 Kio |
| Corps relayés par navigation | 8 Mio / 8 Mio |
| Liens exportés par navigation | 128 / 128, et bornes DOM W4.1 |

Toutes les requêtes consomment aussi les budgets HTTP de mission existants,
y compris les refus après réservation et les erreurs DNS selon leur contrat.
Le plafond de corps doit abaisser celui du worker HTTP avant téléchargement,
sans jamais l'augmenter. Les octets relayés sont un budget de transfert,
distinct du quota des preuves persistantes ; les deux sont appliqués.
Captures et liaisons nouvelles sont comptées dans le quota des preuves.
Un bundle JavaScript trop gros ou une application lente donne une limite
explicite ; ces valeurs ne prétendent pas couvrir toutes les SPA.

## État et preuves

Schéma additif proposé, dont les noms définitifs seront fixés à l'implémentation :

- Navigation : mission/run/route, propriétaire, hash de configuration et de
  profil, réservation, deadline, état et raison de terminaison, arrêt demandé.
- Ressource : navigation, numéro séquentiel, type, URL privée et empreinte,
  méthode, ticket HTTP, empreinte du reçu, état de remise et raison de refus.
- Capture : liens DOM privés bornés, empreinte, sources et tickets utiles,
  limitations ; pas de DOM complet, console, cookie ou capture d'écran par défaut.

La fin d'un échange lie atomiquement son reçu à la ressource. La fin de
navigation lie atomiquement la capture, la couverture et les candidats de
frontière après vérification des reçus associés. Un crash entre ces étapes
laisse des ressources exécutées mais une navigation interrompue, jamais un
rendu complet inventé. Les liens DOM restent des candidats soumis à la
politique avant exploration ; les endpoints fetch/XHR sont identifiés comme
API observées, avec leur provenance, sans être automatiquement déclarés testés.

La récupération ne recharge aucune page et ne renvoie aucune ressource
incertaine. Une reprise explicite peut avancer sur les navigations jamais
commencées. Rejouer une navigation interrompue exige une nouvelle tentative
identifiée et de nouveaux tickets, sans effacer son historique. Les vues
`status/report` restent strictement en lecture seule.

## Parcours CLI prévu

Conserver les commandes HTTP existantes. Ajouter d'abord une action explicite
de découverte navigateur sur un run, sans URL ou script libres :

```text
argos web browse --run-id UUID --public-key reviewer.pub.pem --json
argos web status --run-id UUID --json
argos web report --run-id UUID --json
argos web stop --run-id UUID
```

**`browse` n'existe pas encore.** Il sélectionnera les routes HTML éligibles
du run et les nouveaux candidats DOM, dans la limite signée. Les fichiers
d'installation du navigateur viennent de la configuration d'administration,
jamais de la cible ou du modèle. La sortie conserve UUID, compteurs, hashes,
états et raisons stables ; chemins et valeurs de query restent privés.
Une mission v2 demandant `browse` sera refusée clairement avant lancement.

## Ordre des commits et critères d'acceptation

- [ ] **W4.2a — Contrats et configuration** : v3, budgets, modèles de navigation,
  schéma additif, intégrité et états ; aucun trafic nouveau. Régressions des
  configurations, signatures et reçus v1/v2 compris.
- [ ] **W4.2b — Relais HTTP durable** : liaison ticket/ressource, remise après
  commit, deadlines imbriquées, contrôle d'arrêt et réservation des preuves.
  Essais positifs et injections de pannes avant exposition CLI.
- [ ] **W4.2c — Découverte CLI et qualification** : `browse`, frontière DOM/API,
  vues expurgées, reprise explicite et essais Chromium + HTTP/TLS réels sur
  serveurs de test locaux. Mettre à jour installation, exemples et bilan.

Chaque sous-lot donne un commit conventionnel court. Aucun n'est déclaré
terminé sur la seule présence du code ou d'un test simulé.

Acceptation finale de W4.2 :

- [ ] Depuis l'URL seule : HTML → script → fetch JSON → lien DOM → nouvelle
  page, avec provenance vérifiable et résultat visible dans `report`.
- [ ] Chaque requête parvenue au serveur possède ticket et reçu correspondants ;
  aucun hôte auxiliaire, port interdit, autre origine ou méthode interdite contacté.
- [ ] Signature invalide/expirée, ancien profil, configuration modifiée,
  DNS interdit et certificat incorrect refusés par le même runtime HTTP.
- [ ] La concurrence HTTP égale à un fonctionne ; les compteurs navigateur
  n'affaiblissent ni cadence globale ni quota HTTP, même après redémarrage.
- [ ] Budgets de durée, ressources, corps, preuves et URL épuisés séparément :
  arrêt explicite, résultats partiels, aucune relance cachée.
- [ ] Annulation, révocation et crash pendant démarrage, attente de débit,
  connexion, réponse et commit : descendants nettoyés, historique conservé,
  aucune ressource fournie après un refus d’activité observé ou une preuve
  non validée.
- [ ] Corps, cookies et marqueurs privés absents des sorties, logs ordinaires
  et reçus publics ; bases anciennes toujours consultables.
- [ ] Suites Python 3.12/3.14, lint, typage, wheel/sdist et essais hôte passent.

## Suite vers le pentest professionnel

Après W4.2 : W4.3 ajoute redirections, interactions, sessions anonymes et comptes
optionnels séparés. En parallèle au sens du planning, les premières capacités
W5/W6 apportent tests méthodologiques, preuves et restitution ; il n'est pas
nécessaire d'attendre un catalogue exhaustif pour commencer W7 sur un petit
ensemble vérifié. W7 doit ensuite choisir ses hypothèses et actions, interpréter
les observations et replanifier sans intervention entre les actions prévues.
W8 mesure les résultats face aux références et à une revue experte. W9 prépare
la livraison et les pilotes clients sur un périmètre annoncé honnêtement.

Le dernier bilan W4.1, antérieur à cette préparation documentaire, est de
760 tests locaux sous Python 3.12 et 3.14. Ce nombre mesure les régressions
du logiciel ; il ne mesure pas le taux de vulnérabilités qu'Argos sait trouver.
