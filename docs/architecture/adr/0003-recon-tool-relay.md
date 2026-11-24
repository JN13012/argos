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

### Extension M2.1.1 — Installations administrateur (24 novembre 2026)

Le registre standard-library TOML complète les installations système ; il
n'élargit pas les capacités ni les permissions de mission. Une installation
administrateur ne permet l'exécution externe à `/usr` que pour les trois
identifiants existants, avec binaire ELF vérifié et ressources Nmap bornées.
Les helpers réseau et le socle `/usr` en lecture seule restent inchangés.

Les fichiers choisis sont copiés dans des memfd scellés, revérifiés par SHA-256,
puis remis à Bubblewrap par `--ro-bind-data` vers des destinations fixes sous
`/opt/argos-tools/<id>`. Aucun montage du HOME, du dossier Pentest entier ou de
ses résultats. Nmap reçoit uniquement ses données de reconnaissance et son
runtime NSE de catégorie version, déjà implicite avec `-sV` ; Gobuster/ffuf
reçoivent leur seul exécutable. Les profils lient ces ressources à l'exécution.

Le guardian de confiance dispose de 64 Mio par fichier et 1 024 descripteurs
pour préparer ces instantanés (au plus 512 ressources Nmap). Avant toute
exécution d'outil/bootstrap, `prlimit` rétablit **les plafonds soft et hard**
FSIZE/NOFILE du WorkerLimits initial, dans le sandbox. Cgroups, CPU, mémoire,
échéances, surveillance des sorties et règles réseau restent identiques.
Les constantes de scellement suivent l'ABI Linux quand Python ne les exporte
pas ; un noyau sans scellement bloque l'exécution, sans repli hôte.

Cette préparation locale ne prouve pas une authenticité signée de la distribution
ni une résistance à l'administrateur qui contrôle le registre et le runtime.
Les scripts NSE hors catégorie version, les bibliothèques privées additionnelles
et les outils Hashcat/John n'acquièrent aucune nouvelle capacité opérationnelle.
