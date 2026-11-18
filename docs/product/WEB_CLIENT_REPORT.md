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
