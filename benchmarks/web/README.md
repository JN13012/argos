# Mesurer le pentest web d'Argos

**W1.2 préparé hors ligne** : ce dossier contient la sélection destinée au futur
runner d'évaluation. Il ne contient ni application vulnérable, ni solution,
ni flag, ni résultat de pentest. Aucun score n'est annoncé.

Le fichier [manifest.json](manifest.json) appartient à l'évaluateur et ne doit
pas être monté dans le worker ni fourni au contexte du modèle. Il distingue :

- 12 cas référencés : 8 en boîte noire externe, 4 guidés CVE-Bench séparés.
- 8 cas de développement et 4 réservés à l'évaluation ultérieure.
- 12 témoins corrigés à construire/qualifier, un par défaut sélectionné.
- 6 cas de comportement à ajouter : soft-404, SPA, session inaccessible,
  redirections internes/externes et application sans constat attendu.

Les témoins et cas de comportement restent `planned`, les défis `not_run`.
Ils ne comptent pas comme tests cyber réussis. Les tests Python vérifient
l'intégrité du manifeste et la séparation des entrées, pas la réussite d'un scan.

## Références figées

Sources consultées le 16 novembre 2026 :

| Suite officielle | Commit | Conditions du dépôt consultées | Rôle et limite |
| --- | --- | --- | --- |
| [XBOW](https://github.com/xbow-engineering/validation-benchmarks/tree/a16cb1ba0701b20d63913846536fc7b0672082af) | `a16cb1ba0701b20d63913846536fc7b0672082af` | Apache-2.0 | Six défis ; régression uniquement, le README les déclare saturés et connus des modèles |
| [CVE-Bench](https://github.com/uiuc-kang-lab/cve-bench/tree/9fb3e068f260b00dd899ef87951b88e9c60061f1) | `9fb3e068f260b00dd899ef87951b88e9c60061f1` | Apache-2.0 | Quatre cas guidés ; les variantes `zero_day` fournissent aussi un contexte utilisateur et des objectifs précis, ce qui n'est pas notre boîte noire stricte |
| [Juice Shop](https://github.com/juice-shop/juice-shop/tree/266448aba68cd8ba5915f526a128da4fa7bc3f9f) | `266448aba68cd8ba5915f526a128da4fa7bc3f9f` | MIT | Deux propriétés distinctes sur une SPA ; code public et défis connus, commit de développement et non release qualifiée |

Le manifeste contient les SHA-256 du README, de la licence et des fichiers
référençant chaque cas. Les fichiers ont été comparés aux copies source dans
`/tmp`, sans exécuter leurs applications. Le code, les contenus et les images
ne sont pas importés dans Argos. Les licences des composants, dépendances et
contenus restent à examiner avant redistribution ; les références de licence
ci-dessus ne couvrent pas toute une image construite.

## Sélection consultable par le réviseur

| ID interne | Cas source | Profil | Répartition |
| --- | --- | --- | --- |
| web-001 | XBOW XBEN-001-24 | Boîte noire | Développement |
| web-002 | XBOW XBEN-004-24 | Boîte noire | Développement |
| web-003 | XBOW XBEN-006-24 | Boîte noire | Développement |
| web-004 | XBOW XBEN-009-24 | Boîte noire | Développement |
| web-005 | XBOW XBEN-019-24 | Boîte noire | Réservé |
| web-006 | XBOW XBEN-020-24 | Boîte noire | Réservé |
| web-007 | CVE-2024-2624 | Guidé | Réservé |
| web-008 | CVE-2024-3408 | Guidé | Développement |
| web-009 | CVE-2024-32980 | Guidé | Développement |
| web-010 | CVE-2024-37831 | Guidé | Développement |
| web-011 | Juice Shop loginAdminChallenge | Boîte noire | Développement |
| web-012 | Juice Shop reflectedXssChallenge | Boîte noire | Réservé |

Une même application présentant deux failles ne devient pas deux applications
indépendantes. Les noms de CVE, catégories et clés ci-dessus restent du côté
évaluateur. Les cas réservés sont publics et ne constituent pas un jeu inconnu
des modèles ; une variante métier originale reste nécessaire avant W8. Leur
séparation évite les ajustements locaux sur les mêmes cas de validation.

## Contrôler sans démarrer de cible

Depuis la racine du dépôt :

```bash
.venv/bin/python -m scripts.check_web_benchmarks
```

La sortie donne 12 cas, 8 boîte noire, 4 guidés, 4 réservés, 12 témoins prévus
et 6 comportements prévus. Pour comparer les fichiers d'un checkout déjà
présent, sans installation ni accès réseau :

```bash
.venv/bin/python -m scripts.check_web_benchmarks --source xbow=/chemin/checkout-xbow
```

Les noms de source acceptés sont `xbow`, `cve`, `juice`. La comparaison porte
sur les fichiers référencés, pas sur l'intégralité d'une image ou d'un dépôt.
Un fichier modifié ou un chemin sortant du checkout est refusé.

## Entrée minimale pour le futur agent

Exemple avec URL de démonstration syntaxique ; aucune connexion n'est faite :

```bash
.venv/bin/python -m scripts.check_web_benchmarks \
  --agent-case web-001 --target-url https://target.example.com/
```

Le résultat est une configuration W1.1 : nom générique, URL attribuée, origine
exacte, budgets, aucun compte et aucune écriture activée. Les tags, références,
flags, oracles, solutions et identifiants du cas ne sont pas transmis. Les
profils guidés ne peuvent pas être exportés comme boîte noire par cette commande.

Cet export est une projection de données, pas une frontière d'isolation. Le
futur runner doit attribuer l'URL d'application correcte, réserver une origine
ou un port distinct pour la notation et empêcher le modèle d'atteindre les
fichiers sources et services de contrôle. Les scoreboards et interfaces de
challenges accessibles dans l'application, notamment Juice Shop, devront
être cachés/bloqués sans fournir leurs chemins au modèle. Une URL de notation
erronément passée au paramètre ne peut pas être identifiée par W1.1 seule.

## Déploiement et notation restant à réaliser

1. Construire les images depuis les sources figées ; verrouiller base images,
   dépendances et digests finaux. Plusieurs Dockerfiles amont utilisent des
   tags mobiles : un commit source seul ne rend pas le build reproductible.
2. Mesurer RAM, CPU, stockage et temps de démarrage sur amd64 ; aucune mesure
   de ressources n'a encore été faite. Définir les plafonds effectifs avant run.
3. Ajouter le profil réseau privé explicite et le transport W2. La configuration W1.1 reste externe ; la v2 W2.1 fournit désormais un
   profil privé signé et une politique hors ligne, sans transport. L’export
   v1 ne contourne pas son refus des IP privées/nom interne `target` et ne
   suffit pas à lancer ces suites.
4. Adapter la notation : comparaison au flag injecté côté évaluateur pour
   XBOW ; état serveur du challenge Juice Shop ; grader CVE-Bench appelé par
   l'évaluateur, jamais par le modèle. Un simple HTTP 200 ne valide aucun cas.
5. Examiner chaque issue CVE-Bench applicable. Le profil sélectionné écarte DoS,
   modifications massives de données et exécution de code ; ne pas annoncer
   une comparabilité avec le score complet amont. Les critères restants sont
   des candidats dont l'applicabilité au cas n'a pas été démontrée.
6. Produire les témoins corrigés, vérifier la correction avec reproduction
   indépendante et rejouer le même test. `planned` ne devient pas `passed`
   parce que l'agent ne trouve rien. Tester aussi les six comportements.
7. Figer le budget modèle avant W7, faire trois répétitions, conserver preuves,
   coûts, durée et interventions ; rapporter les résultats par profil/famille.

La majorité boîte noire est maintenue sans donner les descriptions pédagogiques
amont au modèle. Certains défis peuvent exiger inscription, écriture ou accès
spécifique : leur faisabilité doit être vérifiée avant exécution ; à défaut
ils restent bloqués, sans pouvoir élargir eux-mêmes la configuration.

W1.2 livre la préparation et ses contrôles hors ligne. Images, oracles, témoins
et exécution restent non qualifiés ; W1 n'est pas déclaré entièrement clos.
La [spécification W1.3](../../docs/product/WEB_HTTP_EXECUTION.md) est désormais
livrée, ainsi que les [contrats W2.1](../../docs/product/WEB_HTTP_POLICY.md).
La prochaine implémentation est W2.2, le transport HTTP, avant stockage et CLI. Les critères réels seront mesurés avec W2–W7, puis W8.
