# Premier rapport client web

**Livré et validé localement.** Cette tranche ouvre W6 à partir des preuves déjà
disponibles. Elle est indépendante des sessions W4.3c.

## Résultat à livrer

À partir d’une mission web enregistrée, générer un rapport Markdown destiné
au client. Argos remplit les sections à partir des données locales. Un guide
et un exemple synthétique montrent comment le réviseur complète le contexte,
qualifie l’impact métier et relit le document avant remise.

Commande CLI avec l’identifiant d’une exécution existante :

```bash
python -m argos web report --run-id UUID --format markdown
```

Le rapport Markdown est écrit sur la sortie standard. Pour ce premier format,
`--run-id` est requis et `--json` est incompatible avec `--format markdown`.
Les usages actuels de `status` et `report`, dont `--json`, restent compatibles.
La génération utilise la lecture seule existante sans créer de requête, ouvrir
le navigateur ou charger un modèle. Elle reste disponible après expiration de
la mission. Le PDF et la mise en page aux couleurs du client viendront ensuite.

## Contenu et sources

| Section | Données à reprendre |
| --- | --- |
| Synthèse | Identifiant et état de l’exécution, résultats établis et limites principales. Toute gravité ou conséquence métier non évaluée reste à qualifier. |
| Périmètre et couverture | Surfaces publiques observées, types de parcours examinés, refus et blocages. Distinguer les échanges HTTP exécutés, les routes ou API observées et les contrôles de sécurité effectués. |
| Constats | Reprendre le constat de redirection existant lorsqu’il est confirmé, avec identifiants et empreintes des preuves, effet observé et recommandation de correction. Les autres observations restent distinctes. |
| Recontrôle | Résultat initial et dernier recontrôle lié au constat, si disponible. Un résultat non reproduit ou inconclusif conserve le constat historique et ses preuves. |

S’appuyer sur les projections existantes du [rapport web](WEB_CLI_DISCOVERY.md)
et du [recontrôle](WEB_OPEN_REDIRECT.md). Le rapport se limite aux valeurs
expurgées de ces projections, aux références de preuve et au texte produit par
Argos. Ne pas réinjecter les URL privées, en-têtes, corps, cookies ou secrets.
Le rendu accepte les identifiants et empreintes sous leur forme canonique et
limite les états et motifs à des valeurs connues. Le [guide](../development/WEB_REPORT_GUIDE.md) explique
comment documenter les preuves manquantes et les zones non testées, notamment
les parcours auxquels une mission anonyme n’a pas accès.

Un [exemple synthétique](../development/examples/web-client-report.md) montre
un constat confirmé à l’origine puis non reproduit au recontrôle.

## Matrice de couverture W5.1

Le rapport Markdown présente les 20 familles `WEB-*` du
[catalogue Argos](WEB_CAPABILITIES.md), toujours dans le même ordre. Le rendu
repose sur les projections existantes. Il n’ajoute ni requête, ni données à la
base, ni champ au JSON historique.

| Famille | Règle d’attribution |
| --- | --- |
| `WEB-01` | Observé dès qu’un échange de découverte aboutit sur une page. Les requêtes témoins ne comptent pas comme pages observées. |
| `WEB-02` | Observé dès qu’un appel API ou un lien DOM est relevé. Une observation ne détermine pas la sécurité de l’API. |
| `WEB-04` | Compter séparément les contrôles et recontrôles confirmés, non reproduits, inconclusifs et sans résultat. Le statut « Contrôle ciblé effectué » concerne la redirection externe enregistrée. « Partiel » combine des résultats conclusifs et des cas encore incertains. |
| Autres familles | Non testé en l’absence de contrôle pris en charge par cette projection. L’applicabilité n’est pas déduite du silence des données. |

Cette matrice rend visibles les lacunes de la mission. Elle ne calcule aucun
pourcentage OWASP et ne constitue pas une attestation de conformité.

Validation W5.1 : huit tests de rapport, 966 tests réussis sous chacun des
interpréteurs Python 3.12 et 3.14 avec `python -m pytest -q -o
faulthandler_timeout=30`. Les 86 essais hôte restent hors de cette suite
régulière. Ruff, le formatage Ruff et Pyright passent. Les 20 identifiants de
l’exemple ont été comparés au catalogue.

## Export JSON de la couverture

Un tableau de bord ou un outil de revue peut consommer la matrice sans
analyser le Markdown. La commande lit une exécution locale enregistrée :

```bash
python -m argos web report --run-id UUID --format coverage-json
```

L’objet contient `schema_version` (actuellement `1`), `mission_id`, `run_id`,
`configuration_sha256` et `families`. Les 20 familles apparaissent dans
l’ordre du catalogue. Exemple d’une entrée de `families` :

```json
{
  "family_id": "WEB-02",
  "family": "SPA et API observées dans le navigateur",
  "status": "observed",
  "detail": "1 appel(s) API et 2 lien(s) DOM relevé(s).",
  "counts": {"api_observations": 1, "dom_links": 2}
}
```

Pour l’intégration, utiliser `family_id`, `status` et `counts`. `family` et
`detail` sont des libellés français. Les états stables sont `observed`,
`not_observed`, `not_tested`, `inconclusive`, `partial` et
`targeted_check_completed`. Le dernier état ne qualifie que le contrôle
nommé dans la ligne.

- `WEB-01` expose `completed_page_exchanges`.
- `WEB-02` expose `api_observations` et `dom_links`.
- `WEB-04` expose `confirmed`, `not_reproduced`, `inconclusive` et `no_result`.
  Ces valeurs comptent les enregistrements de contrôle ou de recontrôle.
  Une confirmation et son recontrôle peuvent donc compter dans deux colonnes.
- Les autres familles exposent `counts: {}` et restent `not_tested`.

Une erreur de lecture ou un identifiant inconnu renvoie un code de sortie
non nul et un objet `error`. `--format coverage-json` exige `--run-id` et
s’utilise seul, sans `--json`. Les références de preuve détaillées restent
dans le rapport existant. L’export de couverture contient des compteurs,
des identifiants de mission et des libellés, sans URL, paramètre ou contenu
récupéré auprès de la cible.

Validation de l’export : les tests CLI couvrent la compatibilité du JSON
historique, la stabilité de deux exports, le recontrôle, la distinction entre
API observée et API testée, et l’intégrité de la base. La suite régulière
`python -m pytest -q -o faulthandler_timeout=30` passe avec 966 tests sur
Python 3.12 et 3.14. Les 86 essais hôte n’ont pas été activés. Ruff,
le formatage Ruff et Pyright passent.

## Comparer deux exports

Conserver un export avant et après une reprise ou un recontrôle permet de
repérer les changements sans rouvrir la base de mission :

```bash
python -m argos web compare-coverage --before avant.json --after apres.json
```

Les deux fichiers doivent être des exports de couverture v1 de la même
exécution, avec le même identifiant de mission et la même empreinte de
configuration. La commande lit des fichiers locaux ordinaires, au plus 64 Kio
par fichier, sans suivre un lien symbolique final. Elle ne modifie aucun
fichier, n’accède pas au réseau et n’a pas besoin de la base SQLite.

La sortie est un objet JSON de version `schema_version: 1`, avec les trois
références communes et un tableau `changes`. Une famille figure dans ce
tableau si son état ou l’un de ses compteurs a changé. Par exemple, un
recontrôle non reproduit peut ajouter ce changement à `changes` :

```json
{
  "family_id": "WEB-04",
  "status_before": "targeted_check_completed",
  "status_after": "targeted_check_completed",
  "counts": {"not_reproduced": {"before": 0, "after": 1}}
}
```

`changes: []` indique les mêmes états et compteurs. Les libellés de
présentation sont ignorés. L’ordre avant/après est fourni par l’opérateur.
La comparaison porte sur des agrégats et ne vérifie ni l’origine ni les
preuves des fichiers exportés. Pour qualifier une correction, consulter le
constat et son recontrôle dans le rapport client. Les entrées invalides ou
incompatibles donnent `{"error":"invalid_input"}` et un code de sortie `2`.

Validation locale : huit cas de comparaison couvrent les écarts, la lecture
seule et les refus d’entrées. La suite régulière `python -m pytest -q -o
faulthandler_timeout=30` donne 974 réussites sur Python 3.12 et 3.14, avec 86
essais hôte hors de cette suite. Ruff, le formatage Ruff et Pyright passent.

## Index des preuves HTTP

L’index accompagne le rapport lors d’une revue. Il permet de rattacher les
reçus HTTP enregistrés aux routes de découverte, navigations et contrôles de
redirection, recontrôles compris.

```bash
python -m argos web report --run-id UUID --format evidence-json
```

L’objet exporté contient `schema_version: 1`, `mission_id`, `run_id`,
`configuration_sha256` et `receipts`. Chaque reçu est référencé une fois par
`request_id` et `sha256`. Le tableau `references` donne l’identifiant et le
type de chaque élément qui le référence. Exemple d’une entrée de `receipts` :

```json
{
  "request_id": "00000000-0000-0000-0000-000000000028",
  "sha256": "0000000000000000000000000000000000000000000000000000000000000028",
  "references": [{"kind": "redirect_check", "id": "00000000-0000-0000-0000-000000000004"}]
}
```

Les types sont `route`, `navigation` et `redirect_check`. L’export utilise
la projection en lecture seule du rapport, n’émet aucun trafic et reste
stable si la base de mission ne change pas. Une requête sans reçu est omise.
Deux empreintes incompatibles pour un même reçu provoquent une erreur au lieu
de produire un index ambigu.

L’index contient des références et des empreintes, sans requêtes, réponses,
URL, corps, cookies ni secrets. Pour examiner le contenu expurgé d’un reçu
ou interpréter son résultat, utiliser le dossier de mission correspondant.
L’index seul n’authentifie pas les preuves et ne représente pas les requêtes
structurées hors exécution enregistrées par `web request`.

Validation locale : neuf tests de rapport, avec vérification des références,
du recontrôle, de la stabilité, des doublons et des empreintes contradictoires.
La suite régulière `python -m pytest -q -o faulthandler_timeout=30` passe avec
975 réussites sur Python 3.12 et 3.14. Les 86 essais hôte n’ont pas été activés.
Ruff, le formatage Ruff et Pyright passent.

## Consulter un reçu

L’index donne le `request_id` et l’empreinte nécessaires pour retrouver un
reçu dans la base de mission en lecture seule :

```bash
python -m argos web evidence --run-id UUID --request-id UUID_REQUETE \
  --expected-sha256 EMPREINTE_DU_RECU
```

La commande renvoie le reçu sous forme de résumé JSON. Elle vérifie d’abord
qu’il fait partie de l’exécution demandée, puis contrôle les liaisons du reçu
dans SQLite. `--expected-sha256` est facultatif et permet de vérifier une
empreinte relevée dans un export antérieur. Une empreinte différente est
refusée avec `storage_failed`. Un identifiant absent de l’index donne
`invalid_input`. Aucun échec ne renvoie de reçu partiel.

Le résumé contient la date, l’état de l’échange, son motif d’échec éventuel,
le statut HTTP s’il existe, l’état de complétude du corps et les références
de l’index. Les URL, en-têtes et contenus restent hors de la sortie. Le
résumé décrit un échange individuel et ne qualifie pas la gravité, l’impact
ou l’applicabilité d’un constat.

Validation locale : vérification CLI du bon reçu, refus d’une empreinte
différente et d’une requête absente de l’index, stabilité de la base et
sortie expurgée. La suite régulière `python -m pytest -q -o
faulthandler_timeout=30` passe avec 975 tests sur Python 3.12 et 3.14.
Les 86 essais hôte n’ont pas été activés. Ruff, son contrôle de format et
Pyright passent.

## Vérifier un index archivé

Avant la remise du rapport, comparer l’index fourni au réviseur avec la vue
actuelle de l’exécution dans la base privée :

```bash
python -m argos web verify-evidence --run-id UUID --index index.json
```

La commande relit les preuves et leurs liaisons dans une transaction SQLite
en lecture seule, puis compare les identifiants de mission et d’exécution,
l’empreinte de configuration et la liste complète des reçus avec leurs
références. Le JSON peut être reformaté, mais l’ordre des listes de l’export
est requis. Le fichier local doit être ordinaire, de 16 Mio au plus, sans
lien symbolique final ni clé JSON répétée.

- Code `0` : l’index correspond à la vue actuelle. La sortie JSON indique
  les identifiants, l’empreinte de configuration et `verified_receipts`.
- Code `1`, `index_mismatch` : l’index diffère de la vue actuelle. Une reprise
  ou un recontrôle peut avoir ajouté des reçus depuis son export.
- Code `1`, `storage_failed` : la lecture de la base ou le contrôle des
  liaisons de preuve a échoué.
- Code `2`, `invalid_input` : fichier mal formé ou version non prise en charge,
  par exemple.

Cette vérification établit la concordance avec la base locale au moment de la
lecture. Elle ne fournit pas de signature d’archive, ne compare pas le
Markdown et ne rejoue aucune action. Consulter le résumé d’un reçu lorsque
la revue exige le détail d’un échange.

Validation locale : le test CLI couvre l’index valide, le doublon de clé,
l’empreinte modifiée, le reçu manquant et les liaisons altérées dans la base.
Les suites régulières Python 3.12 et 3.14 passent avec 976 réussites chacune
et 86 essais hôte hors suite. Ruff, son contrôle de format et Pyright passent.

## Critères de livraison

- Une exécution avec un constat confirmé montre sa preuve et son historique de
  recontrôle. Une exécution sans constat distingue absence de confirmation,
  zones non testées et blocages, sans conclure que l’application est sûre.
- Un appel API seulement observé reste une observation, même si tous les
  échanges HTTP associés ont abouti. La restitution ne revendique aucune
  couverture OWASP globale.
- Deux exports de la même exécution inchangée donnent le même document. La
  lecture n’écrit pas dans la base et le JSON existant reste compatible.
- Des valeurs synthétiques contenant un secret, un lien ou une balise hostile
  ne divulguent aucune donnée privée et ne deviennent pas du contenu actif.
- L’exemple et le guide permettent au réviseur de distinguer les données issues
  d’Argos des compléments saisis pour le client. Les rapports réels restent
  hors du dépôt.

## Bilan local

Les quatre tests de `tests/test_web_client_report.py` vérifient le rapport avec
recontrôle, la couverture partielle, l’exclusion de texte hostile et les
options CLI. La suite `python -m pytest -q -o faulthandler_timeout=30` donne
962 réussites sous Python 3.12 et 3.14, avec 86 essais hôte hors de cette suite
régulière. Ruff, le formatage Ruff et Pyright passent. Ces essais concernent
la restitution et la non-régression du dépôt. Aucun rapport réel ni résultat
de qualification client n’a été produit.
