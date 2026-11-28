# Recon V2

Base `32b418d38f881405a0fbaf2ed46e5e0a9711ff41`. La qualification M4
reprend les [essais M2.7](RECON_QUALIFICATION.md) et
[la consolidation M2.7.1](RECON_CONSOLIDATION.md).

## M4.1 — Corpus préparé

Le [catalogue](../../benchmarks/recon_v2/corpus.json) fixe six applications
et les empreintes des manifestes historiques. Pour Juice Shop 19, crAPI v1 et
DVWA, réutiliser la composition privée M2.7.1 et ses relais. Le catalogue
contient les digests des services, auxiliaires compris. La recette conservée
dans `.argos/qualifications/m271/compose.lock.json` reste privée. Avant une
campagne, contrôler la recette et les images locales, créer un projet et des
volumes distincts, vérifier réseau interne, écoute locale, état initial et
readiness. Le projet historique et ses volumes servent d'archives. La
qualification du reset et de l'isolation appartient à M4.2b.

Les trois [applications WSGI](../../benchmarks/recon_v2/fixtures.py) sont
indépendantes et utilisent uniquement la bibliothèque standard. Le portail
couvre les liens relatifs et un refus d'identité. La SPA couvre un shell
générique, un appel JSON et un lien généré dans le DOM. Le catalogue REST
publie un contrat OpenAPI et un refus d'identité. Les refus sont simulés sans
comptes ni transactions. Chaque instance future doit servir un seul callable,
sur sa propre origine de test. Leur contrat HTTP peut être vérifié en mémoire
avant tout essai hôte.

Le référentiel est un fichier de l'évaluateur, distinct du code des fixtures et
des entrées de mission. Pour chaque chemin, l'installation, l'exposition, la
visibilité et l'authentification sont des dimensions indépendantes. Une règle
de proxy de préfixe ne confirme pas une route feuille. Les états `unknown`
restent hors des dénominateurs qui exigent une preuve. L'échantillon historique
de 33 chemins et ses témoins négatifs sont conservés. Une réponse HTTP,
y compris un 401 ou un shell 200, demeure une mesure différente de la
présence d'un endpoint.

Après les six applications initiales, viser trois applications locales
admissibles et trois applications réservées originales. Les variantes d'un
même build, les profils TLS et les pannes ne comptent pas comme des applications
supplémentaires. Les jeux de développement et de réserve sont séparés par
application. Les sessions authentifiées restent liées à W4.3c.
