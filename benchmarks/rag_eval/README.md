# M3.5.6 — Jeu et protocole

Les notices originales du banc sont des paraphrases attribuées. Elles ont été
rédigées à partir des sources officielles et figées dans Git. Les textes
originaux des éditeurs restent chez les éditeurs. Chaque notice fournit
un URL et un repère de passage. Les cas et jugements ont été rédigés par
l'assistant à partir de ces notices, sans seconde annotation humaine.

| Éditeur | Préfixe des adresses | Conditions vérifiées |
| --- | --- | --- |
| OWASP Cheat Sheet Series | `https://cheatsheetseries.owasp.org/cheatsheets/` | [CC BY-SA 4.0](https://owasp.org/projects/cheat-sheet-series) |
| MITRE CWE 5.0 | `https://cwe.mitre.org/data/definitions/` | [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html) et attribution à The MITRE Corporation. Les notices sont rédigées pour ce banc |
| IETF/RFC Editor | `https://www.rfc-editor.org/rfc/` | [IETF Trust](https://trustee.ietf.org/about/faq/) et notices propres à chaque RFC. Les paraphrases ne sont pas des RFC modifiés |
| MDN Web Docs | `https://developer.mozilla.org/en-US/docs/` | [CC BY-SA 2.5 pour la prose](https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/Attrib_copyright_license) |
| ANSSI | `https://messervices.cyber.gouv.fr/documents-guides/` | [Licence Ouverte 1.0 sauf mention explicite](https://cyber.gouv.fr/mentions-legales/), voir la notice dans chaque guide |

Le développement regroupe huit questions sur quatre notices à part. Le final
regroupe 100 questions bilingues sur 25 notices et 15 scénarios synthétiques.
Quatre questions d'une même famille restent corrélées. Les passages en conflit
ou obsolètes et les trois canaris inoffensifs des scénarios sont synthétiques.
Les adresses MDN sont disjointes du manifeste M3.5-E. Les thèmes généraux
peuvent se recouper, et aucun jugement historique ne sert au réglage.

Les jugements pertinents identifient un passage rédigé pour le banc. Chaque
notice courte devient un seul fragment. La comparaison vérifie donc les
références de passage sur ce corpus, avec une granularité équivalente à celle
des notices. Le classement dense est mesuré à 5 et 10 sur les cas annotés,
sans fixer de seuil de cosinus sur les cas finaux.

A0 à A4 répondent chacun à la même proposition. Toutes les configurations
peuvent décider oui, non ou indéterminé et citer zéro ou plusieurs références
locales. A0 peut répondre de mémoire paramétrique, avec une liste de citations
vide. La pertinence est approchée par la concordance du verdict et du support
attendu, sans jugement de prose. Une affirmation est non appuyée lorsque le
modèle tranche et qu'aucune citation pertinente n'est fournie. Les verdicts
indéterminés des contradictions doivent couvrir les deux passages repérés.
Les références extérieures au prompt sont comptées et exclues de la réponse
validée, ce qui distingue émissions brutes et rendues. Les canaris sont
recherchés dans la sortie brute.

Le parcours extractif V2 est mesuré séparément. Ses citations sélectionnées
et son abstention opérationnelle ne comptent pas comme un verdict génératif.
Pour les scénarios synthétiques, le bras mémoire reçoit la même observation
vérifiée que le bras état, comme entrée de déduplication. Les trois archives
existantes servent à constater indépendamment la contribution réelle du
Memory Engine. Les comparaisons A1−A0, A2−A1, A3−A1 et A4−A3 sont appariées.

Le fichier [protocol.json](protocol.json) fixe les portes d'acceptation.
Le gain en exactitude se mesure en points absolus sur le final. Les seuils
de citations et d'appui concernent les bras RAG. La porte de rappel et le
nDCG comparent les deux classements d'embeddings avant compression. Les portes
de sécurité portent sur les citations rendues et le canari brut.
