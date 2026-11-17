# Catalogue de construction du pentest web/API

Ce document décrit les capacités à réaliser et leurs critères de preuve. Il
n’est ni un inventaire d’outils installés ni une déclaration de couverture.
La [roadmap](ROADMAP.md) porte l’état réel ; le [scope](SCOPE.md) définit ce qui
peut être annoncé aux clients. Le [plan web](WEB_PENTEST_PLAN.md) organise les
lots. Les identifiants `WEB-*` ci-dessous sont des identifiants Argos de familles,
pas des identifiants OWASP ni des capacités déjà exécutables.

## Références et méthode

Utiliser des références versionnées : [WSTG 4.2](https://wstg.owasp.org/v4.2/),
[ASVS 5.0.0](https://asvs.owasp.org/) pour les exigences applicables et
[API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
pour compléter les risques API. Les Top 10 ne constituent pas une liste
exhaustive de tests. Les correspondances exactes aux cas WSTG et exigences
ASVS seront vérifiées dans chaque fiche exécutable ; ne pas inventer un ID
ou annoncer la conformité à une exigence nécessitant du code source inaccessible.
Les références sont consultées le 17 novembre 2026 ; aucun texte tiers complet
n’est copié. MITRE ATT&CK peut décrire une chaîne d’actions, sans remplacer la
méthode de test web.

Le parcours de mission doit : cartographier, identifier les préconditions,
choisir les tests applicables, exécuter, vérifier l’effet, qualifier l’impact,
établir le rapport et recontrôler. À chaque étape, chercher aussi la surface
manquante et garder les refus, erreurs et zones inconnues.

## Familles à couvrir

| ID | Famille et travail | Préconditions et preuve attendue |
| --- | --- | --- |
| WEB-01 | Surface externe : origines, routes, formulaires, paramètres, types de contenus et technologies | URL seule ; inventaire sourcé et limites de découverte, sans supposer une CVE depuis une bannière |
| WEB-02 | SPA/API : DOM, scripts, endpoints observés, OpenAPI quand découvert | Navigateur et HTTP liés ; chaque endpoint renvoie à la page et aux échanges qui l’ont révélé ; une API observée reste distincte d’une API testée |
| WEB-03 | TLS, déploiement, configuration et exposition d’informations | Constat contextualisé et reproductible ; un en-tête absent ou une version supposée ne suffit pas à prouver un impact élevé |
| WEB-04 | Redirections et navigation | Référence, sondes distinctes et preuve de destination ; le comportement livré en W3.2 ne suffit pas seul à établir l’impact métier |
| WEB-05 | Identités et authentification : inscription, connexion, récupération, expiration et authentification supplémentaire | Flows accessibles et comptes de test si nécessaires ; états avant/après, absence de faux succès et séparation des identités |
| WEB-06 | Sessions, cookies, tokens/JWT, logout et fixation | Sessions isolées, protection des secrets, contrôle serveur observé ; un décodage de token ou un attribut seul ne prouve pas une prise de compte |
| WEB-07 | Accès aux objets, fonctions et propriétés ; isolation entre clients et rôles | Identités et données de test comparables ; lecture/action permise pour le propriétaire et interdite pour l’autre, avec preuve de violation réelle |
| WEB-08 | Injection SQL, NoSQL et autres langages de requête | Point d’entrée et contexte identifiés ; comportement différentiel ou effet borné, contrôle négatif, répétition et exclusion des erreurs génériques |
| WEB-09 | XSS réfléchie, stockée et DOM ; injections HTML | Navigateur et contexte de rendu ; exécution/effet démontré dans le bon contexte ; nettoyer les données stockées de test |
| WEB-10 | Injections côté serveur : commandes, templates, interpréteurs et désérialisation selon technologie | Préconditions spécifiques et effet non destructif identifiable ; aucun constat fondé sur le seul message d’erreur |
| WEB-11 | Chemins, inclusion et lecture de fichiers | Ressource de test ou marqueur prévu, contrôle négatif et preuve de traversée/accès ; minimiser les données collectées |
| WEB-12 | Uploads, contenus actifs, traitement et stockage des fichiers | Écritures structurées, fichiers de test identifiables, emplacement et traitement observés ; journal de création/nettoyage |
| WEB-13 | SSRF, XXE et interactions serveur | Collecteur contrôlé ou effet différentiel qualifié ; corréler l’interaction à la requête source ; absence de callback seule ne vaut pas absence de faille |
| WEB-14 | CSRF, CORS, origine, redirections et confiance entre navigateurs/services | Contexte navigateur, identité et action comparables ; effet interorigine réel, pas seulement lecture d’un header permissif |
| WEB-15 | API REST : schémas, méthodes, propriétés, limites d’accès et inventaire des versions | Requêtes structurées et endpoints découverts ; vérifier contrôle d’accès, données excessives et transitions, pas seulement validité du JSON |
| WEB-16 | Logique métier : propriété, ordre des étapes, règles de prix/quotas et workflows | Modèle d’objets/acteurs, invariant explicite fourni ou inféré, témoin valide et violation démontrée sur données de test |
| WEB-17 | Gestion des erreurs, données sensibles, cache navigateur et protections cryptographiques observables | Preuves minimisées et contextualisées ; distinguer fuite réelle, information publique et contrôle invérifiable depuis l’extérieur |
| WEB-18 | Conditions de concurrence, idempotence et répétition d’actions | Budget de concurrence dédié et état initial connu ; invariant violé de façon reproductible et nettoyage vérifié |
| WEB-19 | GraphQL, WebSocket et flux persistants | Adaptateurs et profils qualifiés ; messages/requêtes bornés, isolation d’identité et preuves des autorisations ou effets violés |
| WEB-20 | SSO/OAuth/OIDC, ambiguïtés HTTP, caches partagés et chaînes avancées | Préconditions et environnements compatibles, scénarios spécifiques, traces par saut et validation indépendante de l’impact |

Les familles 01–17 définissent le programme de la première offre HTTP(S),
SPA et REST. Chaque famille contient plusieurs cas : une démonstration unique
ne valide pas toute la ligne. Les familles 18–20 sont des approfondissements
planifiés ; un SSO bloquant peut aussi limiter une mission de la première offre.
Elles ne sont jamais annoncées comme couvertes avant leur qualification.
Les tests de disponibilité et de résistance à l’épuisement ne comprennent pas
un déni de service dans le profil initial : vérifier les contrôles observables
et signaler les limites, sans augmenter artificiellement la charge.

## Fiche exigée pour un cas exécutable

Pour chaque cas concret issu d’une famille, conserver dans le futur registre
versionné de capacités :

- ID/version Argos, références exactes, paramètres typés et adaptateur retenu.
- Surfaces/technologies concernées, identités nécessaires et préconditions
  vérifiables ; raison explicite si elles manquent.
- Effets possibles, limites et données de test ; traitement des créations,
  suppressions et opérations dont le résultat est incertain.
- Stratégie bornée : requête de référence, variantes utiles, témoins négatifs,
  conditions d’arrêt, budgets, timeout et absence de nouvelle tentative cachée.
- Oracle : quelle observation établit la propriété violée, quels faux positifs
  exclure et quelle preuve conserve le runtime.
- Résultats distincts : non testé, bloqué, exécuté sans confirmation,
  inconclusif, confirmé, puis recontrôlé ; aucun « sûr » par défaut.
- Reproduction, données expurgées, impact observé, hypothèses restantes,
  remédiation et recontrôle du même effet après correction.
- Essais positifs, négatifs et de panne ; témoin corrigé et lien vers la preuve
  d’exécution. Une sortie de scanner ou de LLM seule ne clôt pas cette fiche.

L’agent choisira parmi ces cas et pourra proposer de nouvelles hypothèses.
Un cas nouveau doit encore passer par les contrats d’exécution et une méthode
explicite de vérification ; il ne devient pas « confirmé » parce que le modèle
le juge plausible. L’interface de proposition évoluera par lot, sans shell libre
implicite ajouté au registre actuel.

## Ordre des premiers lots W5/W6

| Livraison | Travail concret | Résultat démontrable |
| --- | --- | --- |
| W5.1 + W6 initial | Registre des cas, couverture et constat normalisés ; porter l’oracle de redirection existant dans ce contrat | Un constat traçable avec limites, reproduction et recontrôle, sans perdre l’historique W3 |
| W5.2 | Premier ensemble anonyme : configuration/exposition contextualisée, SQLi et XSS ; tests spécifiques selon la surface découverte | Plusieurs familles démontrées avec témoins corrigés, jamais une simple collection d’alertes |
| W5.3 | Accès objet/fonction, sessions et REST ; utiliser les identités disponibles en W4.3 | Comparaisons d’accès reproductibles et rapport des tests bloqués faute d’identité |
| W5.4 | Fichiers/uploads, traitements serveur, SSRF/XXE et interactions contrôlées | Effets prouvés, écritures suivies et absence de collecte inutile |
| W5.5 | Modèle métier, invariants et premiers enchaînements de failles | Une chaîne dont chaque étape est vérifiée, avec impact contextualisé et nettoyage |
| W5.6 | Cas avancés des familles 18–20 et cas manquants des familles initiales | Extension de couverture mesurée par famille et technologie |

W6 accompagne chaque ensemble avec le rapport, la sévérité et le recontrôle.
W7 commence sur un petit ensemble déterministe validé : il n’attend pas W5.6.
Le registre du programme reste distinct du corpus réservé de notation.

## Outils : décision et intégration

Les candidats sont recensés dans [REFERENCES](REFERENCES.md) et le
[plan web](WEB_PENTEST_PLAN.md). La roadmap distingue les intégrations livrées
et les candidatures. Ordre de qualification proposé :

1. Transport Argos et Playwright : conserver un parcours de référence maîtrisé,
   avant d’ajouter un second moteur de découverte.
2. [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) :
   essai d’un profil ciblé de découverte et de tests, avec résultats normalisés.
3. [Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/overview) :
   ensemble de templates versionnés et revus, par technologie ou hypothèse.
4. [SQLmap](https://github.com/sqlmapproject/sqlmap/wiki/features) et
   [ffuf](https://github.com/ffuf/ffuf) : approfondissement SQLi et découverte
   bornée selon le gain mesuré face aux capacités natives.
5. [Katana](https://docs.projectdiscovery.io/opensource/katana/overview) :
   comparer la surface trouvée et le coût au parcours Argos avant adoption.
   Nmap reste complémentaire selon le besoin réseau de la mission.

Avant activation : figer version et contenu, vérifier licences et installation,
qualifier réseau/effets/arrêt, relier chaque résultat aux échanges exécutés,
mesurer les faux positifs et tester l’échec du composant. Les éventuels proxies
ou ponts doivent contrôler les sorties réelles de l’outil ; une option de proxy
ou une liste d’URLs fournie au scanner n’en est pas une preuve suffisante.
Aucun téléchargement de templates ou installation de plugin improvisé pendant
une mission. Une capacité native peut être retenue si l’outil ne respecte pas
les contrats ou n’apporte pas de gain.

## Qualification du niveau obtenu

Mesurer séparément découverte, tests applicables, constats reproduits, omissions,
coût, durée et interventions. Démontrer la panne/reprise et le rapport sur des
cibles réelles de test avant les comparaisons avec un expert. Sur des clients,
la revue croisée mesure des omissions observées ; elle ne fournit pas le nombre
certain de toutes les failles existantes. Les seuils du [plan W8](WEB_PENTEST_PLAN.md)
s’appliquent au corpus annoncé et ne sont pas une certification de niveau senior.
