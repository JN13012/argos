# M3.2 — Analyste LLM local

Au point de départ `f5d9538`, les références LLM dans l'[architecture
agent](../architecture/AGENTIC_CORE.md) et l'[audit](AUDIT_2026-11-16.md)
décrivaient des composants envisagés ou étudiés. La recherche dans
`argos/` et les dépendances Python n'a relevé ni fournisseur LLM monté ni
client d'inférence. Le [contexte M3.1-E](M31_FOUNDATIONS.md#e--mission-review--context-engine),
ses références vérifiées et le CLI `review` sont réutilisés.

## Utilisation

Avec un serveur Ollama de confiance sur `127.0.0.1` et un modèle GGUF déjà
installé, le CLI produit une synthèse consultative de l'archive privée.

```bash
python -m argos review analyze --db BASE_PRIVEE --mission-id UUID_MISSION \
  --model qwen2.5:0.5b
```

Le port par défaut est 11434, modifiable avec `--ollama-port`. Le délai
global des deux requêtes Ollama vaut 90 s par défaut et se règle entre
1 et 300 s. Le plafond de contexte M3.1-E vaut 8 192 octets par défaut et
se règle entre 4 096 et 16 384. L'appel de génération utilise un contexte
Ollama de 8 192 tokens et au plus 384 tokens de sortie. Le téléchargement
et le lancement du serveur restent des opérations explicites de l'opérateur.
Sur les versions Ollama avec fonctions cloud, désactiver le cloud sur le
serveur avec `OLLAMA_NO_CLOUD=1` et lier le service à la boucle locale.
[Configuration locale d'Ollama](https://docs.ollama.com/faq#how-can-i-disable-ollamas-cloud-features)

## Interfaces et contrat

`LLMProvider.complete(LLMRequest)` est asynchrone. Il renvoie
`LLMCompletion` avec le contenu et les compteurs de tokens, ou une
`LLMError` à code stable. `analyze_mission(..., provider)` lit l'archive,
valide la sélection et assemble le résultat. L'adaptateur `OllamaProvider`
utilise le client HTTP déjà disponible. Il vérifie le modèle via
`POST /api/show` et sollicite `POST /api/chat` en réponse unique avec un
schéma JSON. [API Ollama](https://docs.ollama.com/api/chat)
[Sorties structurées](https://docs.ollama.com/capabilities/structured-outputs)

Le modèle voit un sous-ensemble de champs du contexte expurgé, des
références ordinales et des compteurs de couverture. Les références de
preuve, identifiants de mission, empreintes, détails d'identification du
graphe et textes du journal restent dans Argos. Des candidats de contenu
identique sont regroupés en conservant une référence représentative.
Le client ignore les proxies d'environnement et les redirections. Il
rejette les modèles marqués distants et exige le format GGUF et un nombre
de paramètres dans les métadonnées avant d'envoyer les observations.
Le service local est une dépendance de confiance administrée par
l'opérateur. Les métadonnées de l'API ne constituent pas une attestation
du comportement d'un service remplacé.

Le modèle sélectionne de une à huit références. Le contrat de génération
accepte uniquement un objet comme `{"refs":[1,3]}`, avec des numéros pris
parmi les candidats transmis. Argos rejette les références absentes ou
dupliquées, le JSON invalide et les propriétés supplémentaires comme une
classification proposée. Les états `fact`, `inference`, `contradiction`
et `unknown`, les valeurs et les preuves proviennent du contexte vérifié.
Une catégorie que le
modèle omet conserve une entrée représentative du contexte, indiquée par
`origin: context`. Les choix du modèle portent `origin: model_selection`.
La synthèse est extractive. La qualité du choix dépend du modèle et de
la couverture du contexte. Les entrées écartées par le plafond restent
comptées dans `omitted_items`.

Le résultat `local-mission-analysis-v1` mesure les octets du contexte et
des données envoyées, les tokens signalés par Ollama et les millisecondes
de préparation puis d'appel et validation. Des compteurs non fournis valent
`null`. En cas d'échec de génération, le CLI sort avec le code 1 et
renvoie une erreur typée, les mesures disponibles et `analysis: null`.
Les erreurs distinguent le délai dépassé, le service ou modèle indisponible,
le modèle distant, la réponse invalide, trop grande ou tronquée.
Les erreurs d'arguments suivent le code 2 du CLI de revue.

La demande ne contient aucune définition d'outil. Le modèle ne reçoit ni
accès au terminal ni autorisation de mission. Le client n'archive ni
prompt ni réponse brute. Les éventuels journaux du service relèvent de
la configuration de l'opérateur.

## Qualification

Le runtime Linux [Ollama 0.11.11](https://github.com/ollama/ollama/releases/tag/v0.11.11)
a été vérifié par SHA‑256 et lancé en CPU, avec 16 processeurs logiques
visibles et 15,2 Gio de RAM. [Qwen2.5 0.5B Q4_K_M](https://ollama.com/library/qwen2.5:0.5b)
est le modèle qualifié. Son manifeste est
`a8b0c51577010a279d933d14c2a8ab4b268079d44c5c8830c0a93900f1827c67`
et toutes ses couches ont été vérifiées. Le binaire et les poids publics ont
été préparés avant l'essai. Durant l'inférence, le serveur temporaire et
Argos partageaient un espace réseau avec la seule interface loopback.

Les 21 tests de `tests/test_local_llm_analyst.py` utilisent des fournisseurs
simulés ou un transport HTTP synthétique. Ils couvrent les références
hallucinées ou dupliquées, l'injection de contenu, la préservation des
contradictions, l'indisponibilité, la réponse tronquée et le timeout global.

| Archive M2.7.1 | Préparation du contexte | Appel Ollama et validation | Tokens entrée / sortie | Sélections fait / inférence / inconnue |
| --- | ---: | ---: | ---: | ---: |
| crAPI, premier chargement | 845 ms | 9 319 ms | 776 / 42 | 1 / 2 / 5 |
| DVWA, modèle chargé | 711 ms | 4 804 ms | 666 / 42 | 2 / 3 / 3 |
| Juice Shop, modèle chargé | 2 031 ms | 4 642 ms | 759 / 42 | 1 / 1 / 6 |

Les 24 références sélectionnées dans le rejeu final existent dans leurs
contextes et ont été reliées à leurs preuves. Les trois bases sont restées
identiques octet pour octet. Les synthèses incluent chaque fois des faits,
des inférences et des incertitudes. Les archives ne contenaient aucune
contradiction signalée. Ce cas est couvert par la fixture. Le premier
schéma, qui demandait aussi au modèle de recopier chaque état, a rejeté
la réponse Juice Shop. Le rejeu avec le schéma final accepte les trois
archives. La mesure est une exécution par archive sur cet hôte et la
sélection reste sensible au modèle et à la taille du contexte.

## Vérifications locales

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pyright
python -m pytest -q -o faulthandler_timeout=30
git diff --check
```

Les 21 cas du lot passent sous Python 3.12.15 et 3.14.6. La suite régulière
compte 1 229 réussites et 121 tests ignorés par interpréteur. Les essais
hôte optionnels n'ont pas été activés.
