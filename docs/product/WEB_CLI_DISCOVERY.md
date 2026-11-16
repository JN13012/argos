# W3.1 — CLI web et découverte déterministe

Argos peut maintenant partir d'une URL, explorer les liens HTML inclus et
conserver une surface observée depuis le terminal. Il utilise le runtime HTTP
signé, les tickets et le worker isolé existants. Cette étape réalise la
découverte anonyme ; elle ne confirme aucune vulnérabilité et ne constitue pas
encore un pentest web complet. La première capacité de vérification reste W3.2.

## Commandes livrées

```bash
python -m argos web init https://app.example.com --json
python -m argos web plan --mission-id UUID --json
python -m argos web activate --mission-id UUID --approval approval.json --public-key reviewer.pub.pem --json
python -m argos web run --mission-id UUID --public-key reviewer.pub.pem --json
python -m argos web status --mission-id UUID --json
python -m argos web stop --run-id UUID --json
python -m argos web resume --run-id UUID --public-key reviewer.pub.pem --json
python -m argos web report --run-id UUID --json
```

Toutes acceptent `--db`, par défaut `.argos/web/missions.sqlite3`. Le répertoire
est créé en 0700, la base en 0600 ; un répertoire existant trop permissif est
refusé sans modifier ses droits. `init` accepte une URL ou un domaine et crée
un brouillon v2 externe. `--config fichier.json` remplace la cible pour une
configuration v2 explicite, notamment le profil privé d'évaluation. Un format
v1 n'est jamais converti silencieusement en permission d'exécution.

Le plan est hors ligne : capacités, limites, nombres de graines et d'origines,
empreinte et état. Avec `--public-key`, il vérifie aussi le grant actif exact.
Sans cette option, `grant_verified` reste faux ; consulter un brouillon ne
l'active pas. Les identifiants de mission et de découverte sont distincts.

`activate` importe le grant Ed25519 initial du mécanisme existant. La signature
lie la configuration entière : cibles, exclusions, capacités, limites et effets.
Le runtime n'a besoin que de la clé publique. Il n'y a pas de confirmation entre
chaque action admise ; aucune option CLI ne désactive la signature ou TLS.

Une commande `run` reste au premier plan et affiche immédiatement le run ID
sur stderr. Stdout contient un seul résultat JSON si `--json` est présent.
Sans cette option, la sortie texte donne les mêmes états et routes opaques.
Les formes d'argument invalides suivent les erreurs natives d'argparse.

| Code de sortie | Sens |
| --- | --- |
| 0 | Commande réussie ; pour `run/resume`, frontière épuisée dans le périmètre de découverte implémenté |
| 1 | Stockage, propriétaire déjà actif, dépendance d'isolation ou profil indisponible |
| 2 | Entrée invalide, grant ou politique refusés |
| 3 | Découverte partielle ou arrêtée ; résultat et raisons disponibles |
| 130 / 143 | Arrêt propre demandé par SIGINT / SIGTERM |

Le code 0 ne signifie jamais « application sûre » ou « pentest complet ».
`report` est ici une restitution de découverte sauvegardée ; les constats,
la sévérité et le rapport de pentest restent des travaux distincts.

## Préparer le grant initial

La clé de revue et l'émission du grant restent hors du processus d'exécution.
Si une intégration de revue n'est pas encore disponible, l'API existante peut
émettre le fichier sur le poste de l'opérateur de confiance :

```python
import json
import os
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from argos.backend.core.approvals import issue_offline_approval
from argos.backend.core.mission_store import MissionStore

key = load_pem_private_key(Path("reviewer.pem").read_bytes(), password=None)
assert isinstance(key, Ed25519PrivateKey)
with MissionStore(".argos/web/missions.sqlite3") as store:
    record = store.get(UUID("REMPLACER_PAR_UUID_MISSION"))
assert record is not None
approval = issue_offline_approval(
    record, "reviewer", datetime.now(UTC) + timedelta(hours=1), key
)
fd = os.open("approval.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as output:
    json.dump(asdict(approval), output, default=str)
```

`reviewer.pem` et `reviewer.pub.pem` sont une paire Ed25519 déjà provisionnée
par l'administrateur. L'expiration du grant doit précéder celle de la mission.
Le CLI ne génère pas une clé de revue implicite et ne charge jamais de clé
privée pour `run` ou `resume`. Le fichier de grant contient exactement
`mission_id`, `reviewer`, `expires_at`, `signature`.

## Ce que la découverte fait

- Une seule découverte persistante par mission. La frontière commence avec les
  graines signées ; l'ordre est séquentiel, stable selon les liens observés.
- Une requête de contrôle vers un chemin manquant aléatoire par origine incluse,
  avant la première page si le quota d'URLs le permet. Elle consomme les mêmes
  tickets et budgets. Ses liens ne sont jamais explorés.
- Lecture de HTML/XHTML déclaré, au plus 256 KiB, décodé UTF-8 avec remplacement
  des octets invalides. Pas de MIME sniffing, JavaScript, téléchargement d'assets,
  authentification ou soumission de formulaire.
- Extraction des liens `a/area`, application de `base`, résolution des liens
  relatifs et suppression des fragments. Les formulaires et champs nommés sont
  comptés sans conserver leurs valeurs. Les paramètres des URLs sont relevés
  dans la frontière privée ; les vues ordinaires montrent leurs nombres.
- Déduplication par URL canonique complète, sans effacer les valeurs de query.
  Contrôle des origines, exclusions, effets reconnus et downgrade avant admission.
  Aucun DNS n'est lancé pour un candidat hors périmètre.
- Respect de `max_urls`, `max_depth`, `query_variants`, tailles et durée signées.
  La limite d'URLs couvre aussi contrôles et candidats exclus enregistrés. La
  capture privée est bornée à 64 KiB, au plus 256 liens par page et 64 paramètres
  de query par URL. Toute limite reconnue reste visible dans le résultat.
- Redirections incluses avec nouvelle entrée et nouveau ticket à chaque saut ;
  plafonnement des sauts et détection des cycles. Aucun transfert de cookies,
  redirection externe ou repli HTTPS vers HTTP automatique.

L'inspection du corps est un parseur fixe de confiance. Une page ne peut pas
modifier le code, le budget, les clés ou la méthode HTTP. Les chaînes ressemblant
à des instructions restent des données. GET ne prouve pas l'absence d'effet
serveur ; les exclusions et la politique d'effets W2 restent applicables.

## Couverture et confidentialité

401/407, 403 et formulaires avec mot de passe donnent des états explicites
`authentication_required`, `access_denied` ou `login_page`. Le parcours anonyme
n'essaie pas de franchir ces accès. 429/503 gardent les pauses du runtime.

Une page 2xx dont l'empreinte privée correspond exactement au contrôle manquant,
après neutralisation de l'URL reflétée et des espaces, est classée
`suspected_soft_404`. Sa frontière n'est pas développée. Cette heuristique peut
manquer des variantes dynamiques ou confondre un shell SPA commun ; elle ne
prouve pas qu'une ressource n'existe pas. Les applications JavaScript, autres
encodages et APIs non HTML demandent les capacités suivantes du plan.

`completed` signifie seulement que cette frontière est épuisée. Login, réponse
partielle, contenu non interprété ou limite donnent une couverture partielle.
Un lien exclu est distingué d'une URL incluse non testée. Le champ
`confirmed_findings` reste zéro : 200, 302 ou un formulaire ne confirme aucune
vulnérabilité. Les preuves HTTP restent séparées de cette classification de
surface ; l'une ne transforme pas l'autre en constat vérifié.

Les sorties ordinaires contiennent IDs, empreintes d'URL, profondeur, états,
raisons, nombres de paramètres et observations structurées. Aucun corps, cookie,
valeur de query, chemin ou Location original n'est imprimé. La base privée garde
les URL nécessaires à la suite, les liens capturés et les empreintes de contrôle ;
elle est en clair et ne doit pas être publiée comme un rapport expurgé.

## Persistance, arrêt et reprise

L'admission d'une requête et son rattachement à la frontière sont atomiques.
Le résultat HTTP, la preuve, la capture, la mise à jour de route, les nouveaux
candidats et l'audit terminal sont ensuite commis dans une même transaction.
Une erreur injectée après découverte ne laisse ni nouveaux liens ni preuve
orpheline. Les lectures vérifient les captures et leur liaison aux preuves.
Les anciens reçus HTTP sans tables de découverte restent lisibles.

`status/report` ouvrent une connexion SQLite réellement en lecture seule avec
une transaction de lecture cohérente. Ils ne prennent pas le verrou du runtime
et ne réconcilient pas les jobs. Après un crash, `running` peut donc être le
dernier état connu jusqu'à la reprise ; ce n'est pas une preuve de processus vivant.

`stop` écrit uniquement une intention d'arrêt. Le runtime la consulte pendant
l'attente, DNS, le worker et avant commit. Il ne signale jamais un PID conservé.
Ctrl+C et SIGTERM utilisent le même arrêt coopératif. Le verrou reste détenu
jusqu'au dernier checkpoint de découverte, y compris pendant `close()`.

`resume` reprend explicitement les URL encore en file, sous le grant et les
budgets d'origine. Les demandes `pending` sans ticket changent de propriétaire
après revalidation. Les tentatives réservées ou en vol au crash deviennent
`interrupted` et ne sont pas rejouées. Une URL dont l'envoi est incertain ou
annulé reste une lacune ; reprendre ne la transforme pas en succès.
Aucune commande ne remet à zéro les quotas ou ne remplace une mission expirée.

## Qualification et prochaine étape

34 tests supplémentaires couvrent parseur, scopes et effets, paramètres,
frontière bornée, soft-404 suspectée, rollback atomique, capture altérée,
compatibilité des reçus, sorties CLI et lecture sans mutation. Quatre tests hôte
lancent réellement le CLI dans des processus séparés, avec le worker rootless
et une application HTTP locale : découverte et rapport, commande stop, SIGINT,
processus tué puis reprise sans répétition des requêtes déjà envoyées.
**685 tests passent sous Python 3.12 et 3.14**, dont 642 tests réguliers et
43 tests hôte activés explicitement. Ruff, formatage et Pyright passent aussi.
Le contrôle du manifest W1.2 reste valide ; ses défis ne sont pas encore exécutés.

Les dépendances sont celles du [transport W2.2](WEB_HTTP_TRANSPORT.md#validation).
`--slirp`, `--slirp-library` et `--ca-bundle` sont des chemins administrateur
identifiés par empreintes, jamais des champs de requête accessibles au modèle.
Aucune dépendance globale n'est installée par ce lot.

**Suite : W3.2**, première preuve de redirection ouverte : route et paramètre
réellement découverts, réponse de référence, deux marqueurs synthétiques distincts,
absence de DNS/connexion vers ces marqueurs, témoin corrigé et recontrôle.
Ajouter une observation spécifique autorisée dans la preuve ; ne pas déduire
une vulnérabilité du seul header Location. Le navigateur, l'agent LLM et le
catalogue complet de tests restent aux étapes suivantes du plan.
