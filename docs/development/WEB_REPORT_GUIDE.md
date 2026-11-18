# Relire un rapport web Argos

Utiliser l’identifiant d’exécution affiché par le CLI. Conserver le fichier
dans l’espace privé prévu pour la mission.

```bash
umask 077
python -m argos web report --run-id UUID --format markdown > rapport.md
```

Le [rapport synthétique](examples/web-client-report.md) montre la sortie à
relire. Les identifiants et empreintes y sont fictifs.

1. **Préciser le contexte.** Ajouter le client, la période, les applications
   effectivement incluses et l’objectif. Conserver l’identité d’exécution et
   distinguer les compléments du réviseur des données issues d’Argos.
2. **Expliquer la couverture.** Traduire les blocages utiles pour le lecteur.
   Par exemple, « API observée, contrôle d’accès non testé faute de compte ».
   Un résultat sans constat confirmé ne permet pas de conclure à l’absence de
   vulnérabilités.
3. **Relire chaque constat.** Vérifier que les références correspondent aux
   preuves conservées. Expliquer la conséquence métier et la priorité si le
   contexte les établit. Compléter les consignes de correction pour le client
   avec les détails nécessaires et expurgés. Une empreinte référence un reçu,
   elle ne remplace pas la preuve conservée dans le dossier de mission.
4. **Vérifier le recontrôle.** Conserver l’observation initiale et préciser ce
   que le nouveau résultat établit. « Non reproduit » décrit le résultat du
   contrôle, tandis qu’« inconclusif » laisse la correction à vérifier.

Relire aussi les compléments manuels pour écarter les secrets et données
personnelles inutiles. Les rapports réels restent hors du dépôt.
