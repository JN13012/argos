import { useEffect, useRef, useState } from "react";
import { ResultsPanel } from "../features/results/ResultsPanel";
import { AppShell } from "../layout/AppShell";
import "./App.css";

type ApiHealth =
  | { status: "checking" }
  | { status: "available" }
  | { status: "unavailable"; reason: string };

function isHealthyResponse(value: unknown): value is { status: "ok" } {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    value.status === "ok"
  );
}

export function App() {
  const [health, setHealth] = useState<ApiHealth>({ status: "checking" });
  const [retry, setRetry] = useState(0);
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    async function checkApi() {
      setHealth({ status: "checking" });
      try {
        const response = await fetch("/api/v1/health", {
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(
            `L’API a répondu avec le statut HTTP ${response.status}.`,
          );
        }

        const payload: unknown = await response.json();
        if (!isHealthyResponse(payload)) {
          throw new Error(
            "La réponse reçue ne respecte pas le contrat de santé.",
          );
        }
        if (active) setHealth({ status: "available" });
      } catch (error: unknown) {
        if (!active || controller.signal.aborted) return;
        const reason =
          error instanceof Error
            ? error.message
            : "Erreur de connexion inconnue.";
        setHealth({ status: "unavailable", reason });
      }
    }

    void checkApi();
    return () => {
      active = false;
      controller.abort();
    };
  }, [retry]);

  const statusText = {
    checking: "Vérification en cours…",
    available: "API disponible",
    unavailable: "API indisponible",
  }[health.status];

  return (
    <AppShell
      query={query}
      onQueryChange={setQuery}
      ready={health.status === "available"}
      searchRef={searchRef}
      statusText={statusText}
    >
      <main className="workspace" id="main-content" tabIndex={-1}>
        <section
          className={`api-status api-state-${health.status}`}
          aria-busy={health.status === "checking"}
        >
          <span className="status-dot" />
          <span role="status">{statusText}</span>
          <span className="api-caption">Archives locales · Lecture seule</span>
          <button
            type="button"
            onClick={() => setRetry((v) => v + 1)}
            disabled={health.status === "checking"}
          >
            Réessayer
          </button>
          {health.status === "unavailable" && (
            <p role="alert">Échec de la vérification : {health.reason}</p>
          )}
        </section>
        {health.status === "available" && <ResultsPanel query={query} />}
        <footer className="workspace-footer">
          ARGOS · Console de reconnaissance · Aucun scan lancé depuis cette
          interface
        </footer>
      </main>
    </AppShell>
  );
}
