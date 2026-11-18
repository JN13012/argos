# ADR 0002 — Interception de chaque saut navigateur

Date : 18 novembre 2026. Statut : adopté pour W4.3b, qualification décrite dans
le [lot](../../product/WEB_INTERACTIONS.md).

## Problème et options

Chaque sortie Internet doit passer par le runtime HTTP signé et posséder un
ticket/reçu. Le navigateur est confiné sans réseau Internet. Le routage
Playwright ordinaire peut continuer une redirection sans rappeler le handler,
y compris après `route.fulfill` en 3xx : voir la
[documentation officielle](https://playwright.dev/docs/network#redirects).

- Fournir le dernier corps sous l'URL initiale fausserait `location`, les liens
  relatifs et `Response.url` ; cette option est écartée.
- Laisser Chromium suivre le réseau lui-même contournerait le contrôle par
  échange ; le réseau direct et les clients alternatifs restent interdits.
- Modifier une dépendance privée de Playwright serait fragile et demanderait
  une dérivation du paquet verrouillé ; cette option n'est pas retenue.
- Une session Chromium CDP Fetch permet d'intercepter les requêtes et leurs
  sauts, de fournir une réponse réelle et de bloquer sans appeler continue.
  C'est l'option retenue, vérifiée sur les versions Chromium/Playwright du lot.

## Décision

Les missions v5 signent explicitement `browser.redirects` et `redirects.max_hops`.
Les anciennes versions gardent le pilote de routage précédent et refusent les
3xx au rendu. Dans le nouveau mode, une seule session CDP Fetch contrôle les
requêtes de la page ; jamais `Fetch.continueRequest` ni transport Chromium.
`redirectedRequestId` est traduit en identifiants bornés. Le runtime lie la
réponse parente, sa destination normalisée et le saut enfant avant tout DNS.
Les redirections 301/302/303/307/308 restent GET/HEAD ; chaque saut consomme un
ticket, le transfert, la cadence et la deadline du parent.

Le profil lie l'installation, le pilote et les limites signées. Les ressources
et captures évoluent en JSON versionné, sans réécrire les preuves historiques.
La réponse n'est offerte à CDP qu'après commit et vérification ; l'offre ne
constitue pas un accusé d'exécution Chromium. L'URL finale privée est liée à une
ressource document offerte, sans exposer chemin, query ou fragment en public.

## Limites et conséquences

Une origine exacte par navigation reste la limite de cette tranche. HTTP vers
HTTPS ou autre origine dans Chromium est refusé ; la découverte HTTP existante
peut néanmoins trouver une page finale incluse et la choisir comme point de
navigation. Les documents, scripts, fetch/XHR de la page sont interceptés.
Les cibles auxiliaires (worker, popup ou iframe hors processus) arrêtent ce
rendu en état limité ; aucun réseau de secours n'est ouvert. Les iframes de la
page dans le même processus restent soumis à Fetch, sans extraction autonome
de leur DOM. Les service workers et WebSockets restent bloqués.

Les sessions/cookies et actions de formulaire restent W4.3c. La qualification
porte sur les parcours et refus indiqués dans le lot, pas sur toutes les formes
d'applications web. Un changement de version Chromium ou du protocole doit
rejouer cette qualification, notamment les cibles auxiliaires.
