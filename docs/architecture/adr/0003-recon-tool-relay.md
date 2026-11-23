# ADR 0003 — Relais HTTP pour la reconnaissance externe

Décision du 23 novembre 2026, implémentée dans le pipeline
[de reconnaissance](../../product/WEB_RECON.md).

Nmap conserve son chemin réseau contrôlé, une IP littérale, 1–32 ports TCP
et une mission IP signée distincte. Une URL web ne donne pas l’autorisation
de scanner son infrastructure ou les autres clients d’un hébergement partagé.

Gobuster et ffuf sont exécutés comme vrais programmes système dans le worker
réseau existant. Son pare-feu autorise uniquement le port d’un relais privé
local. Le relais traduit leurs chemins relatifs vers le répertoire de la seed
signée, puis soumet chaque GET au runtime HTTP existant. La réponse est remise
après commit et vérification du reçu ; son statut, son corps et ses en-têtes
expurgés sont liés par empreinte. Seuls le statut et le corps arrivent à l’outil.
Les cookies, identifiants et destinations de redirection ne lui sont pas remis.

Un accès direct des outils au site aurait dupliqué les contrôles de périmètre,
DNS, redirection, débit et preuve. Un proxy CONNECT aurait laissé le contenu
HTTPS opaque au contrôleur. Le relais réutilise ces contrôles et la validation
TLS d’Argos, au prix d’une URL technique visible par les outils : seuls leurs
modes d’énumération de chemins GET sont intégrés. Leurs résultats textuels ne
constituent pas des constats ; les observations normalisées viennent des reçus.

Les wordlists et options ne sont jamais du shell. Le jeton du relais et les
listes passent par un descripteur privé vérifié, jamais par les arguments publics.
Les outils ne reçoivent ni
fichier arbitraire de l’hôte ni configuration utilisateur implicite. Le bootstrap
écrit la liste validée dans le tmpfs privé et lance une commande fixe.
La fin du worker annule une requête HTTP encore active. Aucun échec d’isolation
ne choisit une exécution directe sur l’hôte. Les états interrompus sont conservés,
sans reprise ou répétition automatique. Les empreintes locales détectent les
incohérences ; elles ne sont pas une attestation contre un rédacteur de la base.
