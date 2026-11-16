# W1.1 — Configuration web en boîte noire

Livrée en bibliothèque Python. Aucun CLI web, appel DNS, requête HTTP ou agent
n'est ajouté. Le [lot W1](WEB_W1_BLACKBOX.md) suit la suite du développement.

## Charger une mission

Le format pris en charge est **JSON UTF-8**, sans dépendance supplémentaire.
L'exemple YAML du plan initial était une proposition ; il n'est pas un format
accepté. Un fichier minimal contient :

```json
{"name": "Client web", "seeds": ["app.example.com"]}
```

Une URL ou un domaine suffit, sans compte ni documentation. Les origines sont
alors déduites uniquement des graines, sans extension aux sous-domaines ni
changement de protocole. Le domaine nu devient `https://app.example.com/`.
Un [exemple complet](../development/examples/web-mission.json) est disponible.

Depuis la racine du dépôt, avec l'environnement Python du projet :

```python
from argos.backend.attack.web.config import WebMissionConfig

config = WebMissionConfig.load("docs/development/examples/web-mission.json")
assert config.scope.permits_url("https://app.example.com/catalog")
assert not config.scope.permits_url("https://app.example.com/logout")
assert not config.scope.permits_url("https://other.example.com/")
```

`permits_url` est un contrôle de périmètre hors ligne, **pas une autorisation
d'exécuter**. La résolution DNS, le confinement de l'egress, les redirections
et les effets applicatifs restent à implémenter en W2. Un domaine syntaxiquement
valide peut résoudre vers une IP privée ; W1.1 ne le résout pas.

## Contrats effectivement acceptés

- `schema_version` : entier `1` ; `mode` : `external_blackbox` par défaut.
- `name` : titre lisible de 1 à 128 caractères sans contrôles ni espaces en bord.
- `seeds` : liste non vide d'URLs ou de domaines nus, à l'intérieur du scope.
- `scope.origins` : origines HTTP(S) exactes ; schéma, hôte et port sont liés.
  Si `scope` est fourni, `origins` est obligatoire et non vide.
- `scope.subdomain_roots` : domaines racines explicitement étendus ; chaque
  racine exige son origine de base dans `origins`. Seuls ses sous-domaines
  par labels DNS et avec le même schéma/port sont admis. Aucun wildcard implicite.
- `scope.excluded_paths` : exclusions sur toutes les origines incluses. `/admin`
  exclut `/admin`, `/admin/` et ses descendants, pas `/administrator`. `/` exclut
  toutes les routes et ne peut donc pas contenir une graine valide.
- `access.credential_refs` : noms de références facultatifs, jamais les valeurs
  de secrets ; références triées, pas de résolution de coffre dans ce lot.
- `effects.allow_registration` et `allow_test_writes` : booléens stricts, faux
  par défaut. Ces champs n'activent aucun exécuteur dans W1.1.

Les listes sont limitées à 256 entrées chacune ; le fichier et la représentation
canonique à 64 KiB. Les clés inconnues, répétées dans le JSON et les listes
exactement dupliquées sont refusées. Les formes équivalentes normalisées sont
fusionnées. L'objet final est immuable, y compris ses collections imbriquées.
Les erreurs de validation ne reprennent pas les valeurs d'entrée.

| Limite | Défaut | Maximum accepté |
| --- | --- | --- |
| Durée totale, secondes | 1800 | 86400 |
| Requêtes totales | 5000 | 1000000 |
| Requêtes par seconde | 2 | 100 |
| Concurrence | 2 | 32 |
| Délai par requête, secondes | 15 | 120 |
| Octets par réponse | 2097152 | 16777216 |

Ce sont des entiers strictement positifs ; booléens, nombres décimaux et chaînes
numériques ne sont pas acceptés. Le délai par requête ne dépasse pas la durée
totale. Ces limites configurées seront appliquées par W2, sans remplacer les
quotas du worker existant. Les budgets de stockage cumulé et d'exploration
seront ajoutés avant leur usage ; aucun débit réel n'est mesuré par ce lot.

## Normalisation et limites conservatrices

Les hôtes et ports par défaut sont normalisés, IPv6 public est encadré et les
noms IDNA non ambigus sont convertis en ASCII. Une origine ne contient ni
chemin autre que `/`, ni query. Les chemins UTF-8 sont encodés canoniquement.

Sont refusés : identifiants dans l'URL, fragments, protocoles autres que HTTP(S),
adresses littérales non publiques/multicast/réservées et IPv4-mapped, hôtes
locaux ou ambigus, ports invalides, antislashs, contrôles, points finaux du DNS,
segments `.`/`..`, séparateurs encodés, double encodage, doubles slashs et
paramètres de chemin avec point-virgule. Les formes IDNA avec remappage ambigu
sont refusées. Ce choix peut écarter des URLs légitimes : il reste conservateur
jusqu'à la qualification du transport et ne démontre pas un filtrage serveur
universel. Le contrôle de sous-domaines n'utilise pas une base de suffixes
publics ; la racine incluse doit être examinée lors de la configuration.

Le profil ne permet pas une IP privée pour les benchmarks : le profil privé
séparé est encore à construire. Cela ne change pas les scopes IP existants de
Nmap. Les exceptions réseau ne sont jamais déduites du nom d'une cible de test.

## Liaison aux missions existantes

`config.to_record(mission)` utilise `Mission`, `MissionStore`, les signatures
Ed25519 et le cycle brouillon → activation vérifiée → révocation existants.
Le titre doit correspondre. La mission web n'obtient **aucun réseau numérique** :
`scope=None`, une seule action déclarée `web_http_request`, et la configuration
JSON canonique stockée dans une table additive `pentest_web_config`.

Toute la configuration est incluse dans la signature : modifier graines,
origines, exclusions, accès, effets ou limites invalide l'approbation. L'insertion
du brouillon et de sa configuration est atomique. Une configuration manquante,
non canonique ou combinée à des réseaux numériques est refusée. Le format de
signature des missions IP historiques reste identique ; leur table et leur
lecture sont conservées, avec création additive de la nouvelle table.

La politique existante refuse l'exécution HTTP tant que son transport n'est
pas construit. Une mission web ne peut pas autoriser un scan Nmap. Aucun flag
utilisateur ne fournit une approbation ou un contournement de la politique.
Les hashes/signatures n'isolent pas une base SQLite contre un administrateur
capable de modifier le code ou la clé de confiance.

## Validation

Les tests `tests/test_web_config.py` couvrent le chargement sans réseau, les URLs
ambiguës, exclusions/sous-domaines, IPv6/IDNA, JSON malformé et borné, types,
immutabilité, approbation/persistance/révocation, altération de configuration,
rollback atomique et compatibilité avec une base et signature antérieures.
Les régressions complètes du backend et des workers sont exécutées ; les
résultats finaux sont consignés dans le lot W1.
