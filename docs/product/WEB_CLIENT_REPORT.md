# Premier rapport client web

**Préparé, non implémenté.** Cette tranche ouvre W6 à partir des preuves déjà
disponibles. Elle peut être livrée avant les sessions W4.3c.

## Résultat à livrer

À partir d’une mission web enregistrée, générer un rapport Markdown destiné
au client. Argos remplit les sections à partir des données locales. Un guide
et un exemple synthétique montrent comment le réviseur complète le contexte,
qualifie l’impact métier et relit le document avant remise.

Interface CLI proposée, avec l’identifiant d’une exécution existante :

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
Échapper les valeurs issues de la mission pour qu’elles restent du texte dans
le Markdown, y compris les liens, images et balises HTML. Le guide explique
comment documenter les preuves manquantes et les zones non testées, notamment
les parcours auxquels une mission anonyme n’a pas accès.

## Ordre d’implémentation

1. Ajouter le rendu dans `argos/backend/attack/web/reporting.py` à partir de la
   projection en lecture seule et le raccorder à `argos/backend/attack/web/cli.py`.
2. Vérifier un rapport complet et un rapport partiel dans les tests du CLI, à
   partir d’exécutions synthétiques déjà enregistrées.
3. Ajouter le guide et un exemple Markdown synthétique dans `docs/development/`,
   puis actualiser l’index et la roadmap après validation.

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
