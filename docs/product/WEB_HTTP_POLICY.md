# W2.1 — Contrats HTTP et politique hors ligne

Livré en bibliothèque Python, sans transport HTTP, résolveur, réservation
durable ni CLI web. La [spécification W1.3](WEB_HTTP_EXECUTION.md) décrit la
suite W2.2/W2.3. Cette étape produit un plan interne, jamais un droit d'exécuter
hors du runtime. La politique d'exécution actuelle refuse toujours HTTP.

## Configuration v2 explicitement signée

Le chargeur commun `WebMissionConfig.load/from_json/from_dict` distingue v1
et v2. La v1 conserve sa représentation canonique et ses signatures. Aucun
brouillon ou grant actif n'est automatiquement migré : une configuration v2
modifiée requiert une nouvelle approbation de son contenu exact.

Exemple minimal v2 :

```json
{
  "schema_version": 2,
  "name": "Client web",
  "seeds": ["https://app.example.com/"],
  "capabilities": ["http.discover", "http.check_redirect"]
}
```

Voir les exemples [externe](../development/examples/web-mission-v2.json) et
[privé d'évaluation](../development/examples/web-evaluation-v2.json).

```python
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.execution_config import WebExecutionConfig

config = WebMissionConfig.load("docs/development/examples/web-mission-v2.json")
assert isinstance(config, WebExecutionConfig)
assert config.destination.permits_address("1.1.1.1")
assert not config.destination.permits_address("127.0.0.1")
```

Aucun appel DNS/réseau. `config.to_record(mission)` réutilise missions,
persistance et signatures existantes ; la mission doit avoir le même titre.
Les capacités, profils et nouveaux budgets font partie du JSON canonique signé.

## Profils de destination distincts

`external`, par défaut, refuse toute liste de réseaux privés ajoutée. Seules
les IP canoniques globales unicast et non réservées passent le contrôle numérique.
Le mode reste une exploration boîte noire anonyme ; les références de comptes
ne sont pas utilisées par les capacités actuelles.

`evaluation_private` exige 1 à 16 CIDR canoniques explicitement inclus. Les
plages possibles sont RFC1918, ULA IPv6, `127.0.0.1/32` et `::1/128`. Les
réseaux techniques du worker `10.253.0.0/24` et `fd00::/64`, leurs super-réseaux,
les publics, link-local, multicast, IPv4-mapped et `/0` sont refusés.

Le profil privé permet la syntaxe d'un nom interne comme `target` ou d'une IP
incluse. La résolution doit encore donner uniquement des IP des CIDR signés.
Une origine littérale hors profil est refusée dès le chargement. Un nom
syntaxiquement valide ne prouve pas qu'il résout vers un réseau permis.

Le profil est dans la configuration approuvée, jamais dans l'entrée d'une
requête agent. Les exclusions d'origine, port, chemin et sous-domaines restent
identiques dans les deux profils. Cela ne livre pas encore le réseau privé
du runner de benchmarks ni une sortie HTTP vers ces cibles.

## Budgets v2 et capacités

Les limites W1.1 de durée, requêtes, débit, concurrence, délai et réponse restent
présentes. La section `execution` ajoute les valeurs ci-dessous ; chaque défaut
est aussi son plafond. Les compteurs ne sont pas encore appliqués à du trafic.

| Champ | Défaut / plafond |
| --- | --- |
| dns_timeout_seconds | 5 |
| max_dns_addresses | 16 |
| response_header_bytes | 32768 |
| response_header_count | 100 |
| header_line_bytes | 8192 |
| max_redirects | 5 |
| max_urls | 1000 |
| max_depth | 5 |
| query_variants | 10 |
| evidence_bytes | 67108864 |
| url_bytes | 8192 |
| max_retry_after_seconds | 60 |

Types entiers stricts, sans booléen/décimal/chaîne. Seuls profondeur et nombre
de redirections acceptent zéro. La ligne de header ne dépasse pas le total,
et le délai DNS ne dépasse pas celui de la requête. Retries automatiques :
aucun prévu. Le respect du débit, les backoffs, la frontière d'exploration et
les compteurs partagés seront exécutés par W2.2/W2.3/W3, pas par ces dataclasses.

Liste fermée, non vide, triée et signée de capacités : `http.discover` pour
GET/HEAD ; `http.check_redirect` pour GET sans suivi automatique. Aucune
capacité de script, shell, header libre, POST ou écriture n'est disponible.
Les permissions d'effets W1.1 ne créent pas de capacités supplémentaires.

## Entrée agent et frontières de confiance

```python
from argos.backend.attack.web.contracts import WebRequest

# mission_id est fourni par le runtime, pas par le payload du modèle.
request = WebRequest.from_agent(
    mission_id,
    {
        "url": "https://app.example.com/",
        "capability": "http.discover",
        "method": "GET",
    },
)
```

Ce fragment montre l'interface ; `mission_id` provient d'une mission persistée.
Seuls URL, méthode et capacité sont acceptés. Mission/request IDs, IP, Host,
headers, profil, résolution DNS, compteurs et booléen d'autorisation sont
refusés dans ce payload. L'URL est masquée dans le repr du DTO ; il ne s'agit
pas encore d'un système d'expurgation de tout le contenu reçu.

`WebPolicy(database, verifier)` utilise la même base et le vérificateur public
Ed25519. Deux étapes, entièrement sans réseau :

1. `preflight(request, usage=...)` recharge la mission approuvée et active,
   exige v2, vérifie capacité, URL, périmètre et effets connus. Il contrôle le
   snapshot de budget et produit une demande de réservation, pas un ticket.
2. `prepare(request, resolution, usage=...)` recharge encore la mission après
   la résolution fournie par le résolveur de confiance. Il refuse les résultats
   d'un autre nom, futurs, vieux de plus que le délai DNS, trop nombreux ou
   contenant une seule IP interdite. Un littéral ne nécessite pas de résolution
   et ne peut pas être remplacé par une autre IP.

Le plan choisit IPv4 avant IPv6, puis l'adresse numérique la plus basse ; aucun
fallback caché. Il conserve IP, origine/port, Host, identité TLS, hash de config,
limites, budget demandé et mode de redirection. Les adresses DNS et snapshots
sont des objets internes typés ; leur intégrité dépend du futur runtime qui
les produit, pas d'une signature individuelle ou d'un flag du modèle.

Les budgets de la mission, les limites plus restrictives du worker et le temps
restant du snapshot sont comparés. Le corps retenu est plafonné à
`min(response_bytes, worker.output_bytes - 65536 - 4 - 1)` ; absence de marge,
concurrence saturée, compteur épuisé, manque de capacité de preuve ou moins
d'une seconde disponible donnent `budget_exhausted`. La demande réserve la
capacité maximale de sortie ; acquisition atomique, débit, écriture de preuve
et libération de la marge inutilisée restent W2.3.

La liste conservatrice d'effets reconnaît notamment déconnexion, suppression,
inscription et action métier explicite dans le chemin ou la query. Elle peut
bloquer des URLs légitimes et ne démontre pas l'absence d'effet d'un GET inconnu.
Les classifications plus riches et cas ambigus restent à approfondir avant
qualification des parcours. Aucune action active supplémentaire ne découle de
cette heuristique.

`PreparedWebRequest.transport_enabled` vaut toujours faux. Le plan n'est ni
un objet sérialisable depuis l'entrée agent, ni une permission à présenter à
un client HTTP alternatif. Le [confinement W2.2](WEB_HTTP_TRANSPORT.md) est
livré ; verrou, tickets durables, audit et raccordement au runtime restent W2.3.

## Autres contrats livrés

- `WebResponse` : réponse privée bornée, headers ordonnés avec doublons,
  dates conscientes du fuseau, statut final, complétude et référence de preuve.
  Ce DTO ne constitue pas un export expurgé ni une validation de vulnérabilité.
- `WebFailure` : code et phase stables, dispatch explicite, référence de preuve
  éventuelle ; aucune exception brute ou message contenant l'URL.
- `WebEvidence` : contrat de reçu avec identités, hashes et version
  d'expurgation ; aucune preuve n'est effectivement écrite/vérifiée par ce DTO.
- `WebCoverage` : applicabilité et états distincts ; une session manquante ne
  devient pas `not_applicable`. `executed/verified` exigent des références de
  preuve ; leur vérification réelle appartient au stockage W2.3.

## Validation et suite

Les tests bloquent socket, connexion et getaddrinfo pendant tous les nouveaux
cas W2.1. Ils vérifient profils, budgets, périmètre avant DNS, typage des entrées,
altérations signées, revalidation après révocation, refus v1 active, tentative
d'upgrade sans nouvelle signature, DNS mixte/périmé, IP littérales, headers,
états de couverture et conservation des signatures historiques.

Les résultats finaux sont consignés dans le bilan W2.1 du
[lot de réalisation](WEB_HTTP_EXECUTION.md). Aucun service n'est activé.
**W2.2 livré** : [résolveur et transport isolé](WEB_HTTP_TRANSPORT.md), TLS,
entrée privée et framing borné. Suite : W2.3, réservations durables, preuves
et cycle du runtime avant l’ouverture du CLI W3.
