# Argos — Vision

Argos vise une plateforme de cybersécurité IA capable de conduire des missions
en autonomie complète dans un cadre préalablement autorisé, tout en offrant un
mode assisté aux experts. Elle réunit INTEL/OSINT, ATTACK/pentest, puis DEFEND/GRC.

La première valeur commerciale ciblée est le **pentest web et API autonome en boîte noire externe**,
avec comptes facultatifs, rapport étayé et recontrôle, accessible d'abord
depuis le CLI. Le [plan web](WEB_PENTEST_PLAN.md) organise cette priorité.
La qualité attendue d'un pentester senior sera évaluée sur les résultats et
les limites observées avant toute revendication commerciale.

La mission autonome couvre la planification, le choix des outils, l’exécution,
l’analyse des observations, la vérification, la reprise et la restitution.
L’opérateur définit le mandat, les limites et les conditions d’arrêt ; il n’a
pas à confirmer chaque étape comprise dans cette autorisation.

## Principes

- **Autonomie contrôlée par le runtime** : le modèle ne peut ni élargir le
  périmètre ni modifier les permissions de sa propre mission.
- **Capacités utilisables sans modèle** : l’OSINT, les politiques d’exécution et
  les preuves restent indépendants des fournisseurs de LLM.
- **Constats étayés** : distinguer observation, hypothèse, vulnérabilité
  vérifiée et limite de couverture ; conserver source, date et preuve.
- **Reprise et évaluation** : checkpoint, budget, arrêt et relecture des
  résultats sont des fonctions de base de l’autonomie.
- **Modularité** : adopter une brique publique ou construire une capacité
  propre selon des critères mesurés, avec sa provenance et sa licence.
- **Local lorsque pertinent** : ne pas imposer une infrastructure distribuée
  ou distante avant qu’un usage ne la justifie.

## Situation actuelle

Le dépôt contient un CLI OSINT SIRENE, une bibliothèque de reconnaissance Nmap
contrôlée et une application web minimale. Aucun agent ou modèle n’est encore
connecté. La [roadmap](ROADMAP.md) distingue cette réalité de la cible produit ;
le [scope](SCOPE.md) fixe le travail immédiat et le [cadre](CADRE.md) l’usage.
