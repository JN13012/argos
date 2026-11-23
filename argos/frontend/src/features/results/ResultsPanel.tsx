import { useEffect, useState } from "react";
import { Badge } from "../../components/Badge";
import { Button, buttonClassName } from "../../components/Button";
import { BrandLogo } from "../../components/BrandLogo";
import { Icon } from "../../components/Icon";
import { ResultsOverview, stamp } from "./ResultsOverview";
import { Modal } from "../../components/Modal";
import "./ResultsPanel.css";

export type Mission = {
  id: string;
  title: string;
  state: string;
  kind: string;
  targets: string[];
};
export type Source = {
  id: string;
  label: string;
  state: string;
  truncated?: boolean;
  missions: Mission[];
};
type Tool = {
  tool: string;
  state: string;
  reason?: string;
  exit_code?: number;
  errors?: string[];
  entries_with_response?: number;
  wordlist_entries?: number;
  binary_sha256?: string;
  wordlist_sha256?: string;
  stdout_sha256?: string;
  stderr_sha256?: string;
};
type RequestResult = {
  id: string;
  url: string;
  method: string;
  tool: string;
  http_status: number | null;
  state: string;
  classification: string;
  reason: string;
  error: string | null;
  wordlist_provenance: string;
  confidence: string;
  evidence_sha256: string | null;
  verification: string;
  recorded_at: string | null;
};
type Port = {
  target: string;
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  version: string | null;
  confidence: string;
  confidence_note: string;
};
export type MissionResult = Mission & {
  runs: { id: string; status: string; created_at: string }[];
  tools: Tool[];
  ports: Port[];
  requests: RequestResult[];
  routes: {
    id: string;
    url: string;
    state: string;
    reason: string;
    kind: string;
    request_id: string | null;
  }[];
  evidence: {
    id: string;
    tool: string;
    sha256: string;
    xml_sha256: string | null;
    recorded_at: string;
    verification: string;
    error: string | null;
  }[];
  technologies: string[];
  limitations: string[];
  verification: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  reports: { id: string; label: string; url: string }[];
  wordlist_provenance: string;
};
const categories: Record<string, string> = {
  probe: "Sonde / précontrôle",
  spa_generic: "SPA générique suspectée",
  http_error: "Erreur HTTP",
  response_observed: "Réponse confirmée, contenu non exploré",
  route_observed: "Route observée",
  unverified: "Non confirmé",
};
const provenance: Record<string, string> = {
  targeted: "Wordlist ciblée",
  default: "Liste intégrée",
  unspecified: "Provenance non renseignée",
  not_applicable: "Exploration HTTP",
};
async function read<T>(url: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(url, {
    signal,
    headers: { Accept: "application/json" },
  });
  if (!response.ok)
    throw new Error(
      response.status === 409
        ? "La vérification des preuves a échoué. Résultats non affichés."
        : "Les résultats ne sont pas disponibles.",
    );
  return response.json() as Promise<T>;
}

function MissionContent({ result }: { result: MissionResult }) {
  return (
    <>
      <p>{result.targets.join(", ")}</p>
      <p>
        Mandat : <Badge>{result.state}</Badge> · Résultat :{" "}
        {result.runs.map((r) => r.status).join(", ") ||
          "Aucun bilan de pipeline"}
      </p>
      <p>
        Du {stamp(result.started_at)} au {stamp(result.finished_at)} (Paris).
        Durée observée : {result.duration_seconds ?? "inconnue"} s.
      </p>
      <p className="results-notice">
        L’intervalle des preuves ne garantit pas la durée exacte du pipeline.
        Une réponse confirmée ne confirme ni une route fonctionnelle ni une
        vulnérabilité.
      </p>
      <h3>Outils exécutés</h3>
      {result.tools.length === 0 && <p>Aucune exécution archivée.</p>}
      {result.tools.map((t, i) => (
        <details key={`${t.tool}-${i}`}>
          <summary>
            {t.tool} · {t.state} · code {t.exit_code ?? "non archivé"}
          </summary>
          <p>
            {t.reason} {t.errors?.join(", ")}
          </p>
          <p>
            Entrées avec réponse : {t.entries_with_response ?? "—"} /{" "}
            {t.wordlist_entries ?? "—"}
          </p>
          <dl>
            {[
              ["Binaire", t.binary_sha256],
              ["Wordlist", t.wordlist_sha256],
              ["stdout (empreinte seule)", t.stdout_sha256],
              ["stderr (empreinte seule)", t.stderr_sha256],
            ]
              .filter(([, v]) => v)
              .map(([label, value]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>
                    <code>{value}</code>
                  </dd>
                </div>
              ))}
          </dl>
        </details>
      ))}
      <h3>Ports et services Nmap</h3>
      {result.ports.length ? (
        <div className="results-scroll">
          <table>
            <thead>
              <tr>
                <th>Cible / port</th>
                <th>État</th>
                <th>Service / version</th>
                <th>Confiance</th>
              </tr>
            </thead>
            <tbody>
              {result.ports.map((p, i) => (
                <tr key={i}>
                  <td>
                    {p.target}:{p.port}/{p.protocol}
                  </td>
                  <td>{p.state}</td>
                  <td>
                    {p.service ?? "Non identifié"} ·{" "}
                    {p.version ?? "Version non confirmée"}
                  </td>
                  <td>Non qualifiée. {p.confidence_note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>Aucun port archivé.</p>
      )}
      <h3>Routes et endpoints</h3>
      <p>
        {provenance[result.wordlist_provenance]} · {result.requests.length}{" "}
        transactions. Les sondes et réponses génériques restent distinctes des
        routes observées.
      </p>
      {result.requests.length ? (
        <div className="results-scroll">
          <table>
            <thead>
              <tr>
                <th>URL / outil</th>
                <th>HTTP / classification</th>
                <th>Origine / confiance</th>
                <th>Preuve et erreur</th>
              </tr>
            </thead>
            <tbody>
              {result.requests.map((r) => (
                <tr key={r.id}>
                  <td>
                    {r.method} {r.url}
                    <br />
                    {r.tool}
                    <br />
                    {stamp(r.recorded_at)}
                  </td>
                  <td>
                    {r.http_status ?? "Sans réponse"}
                    <br />
                    <Badge
                      tone={
                        r.classification === "http_error"
                          ? "red"
                          : r.classification === "spa_generic"
                            ? "amber"
                            : "neutral"
                      }
                    >
                      {categories[r.classification] ?? r.classification}
                    </Badge>
                    <br />
                    {r.reason}
                  </td>
                  <td>
                    {provenance[r.wordlist_provenance]}
                    <br />
                    {r.confidence === "observed_response"
                      ? "Transaction observée"
                      : "Non vérifiée"}
                  </td>
                  <td>
                    <details>
                      <summary>
                        {r.verification === "verified"
                          ? "Reçu vérifié"
                          : "Preuve absente"}
                      </summary>
                      <p>UUID : {r.id}</p>
                      <code>{r.evidence_sha256 ?? "Aucune empreinte"}</code>
                      <p>
                        État : {r.state} · Erreur : {r.error ?? "aucune"}
                      </p>
                    </details>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>Aucune transaction HTTP archivée.</p>
      )}
      <details>
        <summary>
          Frontière complète : {result.routes.length} routes, y compris non
          testées
        </summary>
        {result.routes.map((r) => (
          <p key={r.id}>
            {r.url} · {r.state} · {r.reason}
          </p>
        ))}
      </details>
      <h3>Technologies</h3>
      <p>
        {result.technologies.length
          ? result.technologies.join(", ")
          : "Aucune identification technologique fiable archivée."}
      </p>
      <h3>Vérification des preuves</h3>
      <p>
        Les reçus disponibles ont été relus et leurs liens d’intégrité vérifiés.
        Ces empreintes ne constituent pas une signature d’authenticité
        indépendante.
      </p>
      {result.evidence.map((e) => (
        <details key={e.id}>
          <summary>
            {e.tool} ·{" "}
            {e.verification === "verified" ? "Preuve vérifiée" : e.verification}{" "}
            · {stamp(e.recorded_at)}
          </summary>
          <p>UUID : {e.id}</p>
          <p>
            SHA-256 : <code>{e.sha256}</code>
          </p>
          <p>
            XML : <code>{e.xml_sha256 ?? "Non archivé"}</code>
          </p>
          <p>Erreur : {e.error ?? "aucune"}</p>
        </details>
      ))}
      <h3>Limitations</h3>
      <ul>
        {result.limitations.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
      <h3>Rapports existants</h3>
      {result.reports.length ? (
        result.reports.map((r) => (
          <a
            key={r.id}
            className={buttonClassName("secondary")}
            href={r.url}
            download
          >
            {r.label}
          </a>
        ))
      ) : (
        <p>Aucun rapport autorisé disponible.</p>
      )}
    </>
  );
}

export function ResultsPanel({ query = "" }: { query?: string }) {
  const [sources, setSources] = useState<Source[] | null>(null);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<{
    source: string;
    mission: Mission;
  } | null>(null);
  const [results, setResults] = useState<Record<string, MissionResult>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const value = await read<{ sources: Source[] }>(
          "/api/v1/results",
          controller.signal,
        );
        if (controller.signal.aborted) return;
        setSources(value.sources);
        const pending = value.sources
          .filter((s) => s.state === "available")
          .flatMap((source) =>
            source.missions.map((mission) => ({ source: source.id, mission })),
          );
        // Bounded read-only loading: no scan, no unbounded request fan-out.
        async function worker() {
          while (pending.length && !controller.signal.aborted) {
            const item = pending.shift()!;
            const key = `${item.source}/${item.mission.id}`;
            try {
              const result = await read<MissionResult>(
                `/api/v1/results/${item.source}/missions/${item.mission.id}`,
                controller.signal,
              );
              if (!controller.signal.aborted)
                setResults((previous) => ({ ...previous, [key]: result }));
            } catch (reason: unknown) {
              if (!controller.signal.aborted)
                setErrors((previous) => ({
                  ...previous,
                  [key]:
                    reason instanceof Error
                      ? reason.message
                      : "Résultat indisponible",
                }));
            }
          }
        }
        await Promise.all(
          Array.from({ length: Math.min(4, pending.length) }, worker),
        );
      } catch {
        if (!controller.signal.aborted)
          setError("Impossible de charger les missions.");
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [retry]);
  const detail = selected
    ? results[`${selected.source}/${selected.mission.id}`]
    : null;
  const detailError = selected
    ? errors[`${selected.source}/${selected.mission.id}`]
    : null;
  const count = sources?.reduce((n, s) => n + s.missions.length, 0) ?? 0;
  const filtered = sources?.map((source) => ({
    ...source,
    missions: source.missions.filter((m) =>
      [m.title, m.id, m.state, m.kind, ...m.targets, source.label]
        .join(" ")
        .toLocaleLowerCase("fr")
        .includes(query.trim().toLocaleLowerCase("fr")),
    ),
  }));
  return (
    <div className="results-dashboard" id="dashboard">
      <section className="welcome-panel panel">
        <div className="welcome-emblem">
          <BrandLogo />
        </div>
        <div className="welcome-copy">
          <p className="eyebrow">CONSOLE DE RECONNAISSANCE</p>
          <h1>Bienvenue sur ARGOS</h1>
          <p>Vos missions. Vos découvertes. Leurs preuves.</p>
          <span className="welcome-tag">
            <Icon name="lock" /> Archives autorisées · Lecture seule
          </span>
        </div>
        <div className="welcome-situation">
          <h2>SITUATION ACTUELLE</h2>
          <p>
            <Icon name="target" /> <strong>{sources ? count : "—"}</strong>{" "}
            missions enregistrées
          </p>
          <p>
            <Icon name="shield" /> Observations de reconnaissance
          </p>
          <a href="#missions">
            Consulter les résultats <Icon name="arrow" />
          </a>
        </div>
      </section>
      <ResultsOverview
        sources={sources}
        results={results}
        errors={errors}
        loading={loading}
      >
        <section
          id="missions"
          className="results-panel panel"
          aria-labelledby="results-title"
        >
          <div className="panel-heading">
            <div className="panel-heading-label">
              <Icon name="target" />
              <h2 id="results-title">MISSIONS ENREGISTRÉES</h2>
            </div>
            <Button
              variant="quiet"
              disabled={loading}
              onClick={() => {
                setSources(null);
                setResults({});
                setErrors({});
                setError("");
                setSelected(null);
                setRetry((v) => v + 1);
              }}
            >
              Actualiser les missions <Icon name="arrow" />
            </Button>
          </div>
          {error && (
            <p className="empty-message" role="alert">
              {error}
            </p>
          )}
          {!sources && !error && (
            <p className="empty-message">Chargement des missions…</p>
          )}
          {sources?.length === 0 && (
            <p className="empty-message">
              Aucune source configurée. Renseigner ARGOS_RESULT_SOURCES côté
              serveur.
            </p>
          )}
          {filtered?.map((source) => (
            <div className="source-group" key={source.id}>
              <div className="source-heading">
                <h3>{source.label}</h3>
                <span>{source.missions.length} mission(s)</span>
              </div>
              {source.state !== "available" && (
                <p role="alert" className="empty-message">
                  Source indisponible.
                </p>
              )}
              {source.truncated && (
                <p className="empty-message">
                  Liste limitée aux 500 premières missions de cette source.
                </p>
              )}
              {source.state === "available" && source.missions.length === 0 && (
                <p className="empty-message">
                  {query.trim()
                    ? "Aucune mission ne correspond à la recherche."
                    : "Aucune mission enregistrée."}
                </p>
              )}
              {source.missions.length > 0 && (
                <div
                  className="results-scroll"
                  tabIndex={0}
                  role="region"
                  aria-label={`Missions · ${source.label}`}
                >
                  <table className="mission-table">
                    <thead>
                      <tr>
                        <th>Mission / cible</th>
                        <th>Type</th>
                        <th>Mandat / pipeline</th>
                        <th>Outils archivés</th>
                        <th>Résultats</th>
                      </tr>
                    </thead>
                    <tbody>
                      {source.missions.map((m) => {
                        const key = `${source.id}/${m.id}`;
                        const r = results[key];
                        return (
                          <tr key={m.id}>
                            <td>
                              <strong>{m.title}</strong>
                              <span className="cell-secondary">
                                {m.targets.join(", ")}
                              </span>
                            </td>
                            <td>
                              <Badge tone="blue">
                                {m.kind === "web" ? "Web / API" : "Réseau"}
                              </Badge>
                            </td>
                            <td>
                              <Badge>{m.state}</Badge>
                              <span className="cell-secondary">
                                {r?.runs.map((run) => run.status).join(", ") ||
                                  (errors[key]
                                    ? "Lecture impossible"
                                    : loading
                                      ? "Chargement…"
                                      : "Aucun bilan")}
                              </span>
                            </td>
                            <td>
                              {r
                                ? [...new Set(r.tools.map((t) => t.tool))].join(
                                    " · ",
                                  ) || "Aucune exécution"
                                : "—"}
                            </td>
                            <td>
                              <Button
                                variant="quiet"
                                onClick={() =>
                                  setSelected({ source: source.id, mission: m })
                                }
                              >
                                Ouvrir{" "}
                                {m.kind === "web"
                                  ? "la mission web"
                                  : "la mission réseau"}
                                <Icon name="arrow" />
                              </Button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))}
        </section>
      </ResultsOverview>
      <Modal
        id="real-mission-dialog"
        open={selected !== null}
        title={selected?.mission.title ?? "Mission"}
        eyebrow="RÉSULTATS RÉELS · LECTURE SEULE"
        closeLabel="Fermer les résultats"
        onClose={() => setSelected(null)}
      >
        {detailError ? (
          <p role="alert">{detailError}</p>
        ) : detail ? (
          <MissionContent result={detail} />
        ) : (
          <p>Vérification et chargement des preuves…</p>
        )}
      </Modal>
    </div>
  );
}
