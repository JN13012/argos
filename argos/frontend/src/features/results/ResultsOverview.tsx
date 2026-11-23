import type { ReactNode } from "react";
import { Badge } from "../../components/Badge";
import { BrandLogo } from "../../components/BrandLogo";
import { Icon } from "../../components/Icon";
import type { IconName } from "../../components/Icon";
import type { MissionResult, Source } from "./ResultsPanel";

export function stamp(value: string | null) {
  return value
    ? new Date(value).toLocaleString("fr-FR", { timeZone: "Europe/Paris" })
    : "Non archivé";
}

export function ResultsOverview({
  sources,
  results,
  errors,
  loading,
  children,
}: {
  sources: Source[] | null;
  results: Record<string, MissionResult>;
  errors: Record<string, string>;
  loading: boolean;
  children: ReactNode;
}) {
  const loaded = Object.values(results);
  // The network mission and its web pipeline can reference the same proof.
  const requests = [
    ...new Map(
      loaded.flatMap((r) => r.requests).map((r) => [r.id, r]),
    ).values(),
  ];
  const evidence = [
    ...new Map(
      loaded.flatMap((r) => r.evidence).map((e) => [e.id, e]),
    ).values(),
  ];
  const ports = new Set(
    loaded.flatMap((r) =>
      r.ports.map((p) => `${p.target}:${p.port}/${p.protocol}`),
    ),
  );
  const reports = [
    ...new Map(
      Object.entries(results)
        .flatMap(([key, result]) =>
          result.reports.map((report) => ({
            ...report,
            source:
              sources?.find((s) => s.id === key.split("/")[0])?.label ??
              "Source autorisée",
          })),
        )
        .map((report) => [report.url, report]),
    ).values(),
  ];
  const tools = [...new Set(loaded.flatMap((r) => r.tools.map((t) => t.tool)))];
  const total = sources?.reduce((n, s) => n + s.missions.length, 0) ?? 0;
  const stats: {
    label: string;
    value: number | string;
    note: string;
    icon: IconName;
    tone: string;
  }[] = [
    {
      label: "Missions archivées",
      value: sources ? total : "—",
      note: `${sources?.length ?? 0} source(s) autorisée(s)`,
      icon: "target",
      tone: "cyan",
    },
    {
      label: "Ports observés",
      value: loaded.length ? ports.size : "—",
      note: "Cible / port / protocole uniques",
      icon: "globe",
      tone: "blue",
    },
    {
      label: "Transactions HTTP",
      value: loaded.length ? requests.length : "—",
      note: "Reçus uniques, sondes incluses",
      icon: "monitor",
      tone: "cyan",
    },
    {
      label: "Erreurs HTTP",
      value: loaded.length
        ? requests.filter((r) => r.classification === "http_error").length
        : "—",
      note: "Ne constituent pas une vulnérabilité",
      icon: "alert",
      tone: "amber",
    },
    {
      label: "Reçus vérifiés",
      value: loaded.length
        ? requests.filter((r) => r.verification === "verified").length +
          evidence.filter((e) => e.verification === "verified").length
        : "—",
      note: "HTTP et Nmap · Dédupliqués",
      icon: "shield",
      tone: "green",
    },
  ];
  const events = [
    ...requests.map((r) => ({
      id: `http-${r.id}`,
      time: r.recorded_at,
      source: r.tool,
      label: `${r.method} ${r.url}`,
      state:
        r.http_status === null ? (r.error ?? r.state) : `HTTP ${r.http_status}`,
      error: r.http_status !== null && r.http_status >= 400,
    })),
    ...evidence.map((e) => ({
      id: `proof-${e.id}`,
      time: e.recorded_at,
      source: e.tool,
      label: `Preuve ${e.id}`,
      state: e.error ?? e.verification,
      error: Boolean(e.error),
    })),
  ].sort((a, b) => (b.time ?? "").localeCompare(a.time ?? ""));
  return (
    <>
      <div className="stats-grid" aria-label="Statistiques des archives">
        {stats.map((s) => (
          <article className={`stat-card panel stat-${s.tone}`} key={s.label}>
            <div>
              <Icon name={s.icon} />
              <h2>{s.label}</h2>
            </div>
            <strong>{s.value}</strong>
            <p>{s.note}</p>
          </article>
        ))}
      </div>
      <p className="archive-coverage">
        {loaded.length} / {total} missions relues
        {loading ? " · Lecture en cours…" : ""}. Statistiques calculées sur les
        résultats chargés, hors sources indisponibles
        {sources?.some((s) => s.truncated)
          ? " et au-delà de la limite de 500 missions par source"
          : ""}
        .
      </p>
      {Object.keys(errors).length > 0 && (
        <p className="results-warning" role="alert">
          {Object.keys(errors).length} mission(s) illisible(s) ou preuves non
          vérifiables. Ouvrir la mission pour consulter l’erreur ; ses résultats
          sont exclus des statistiques.
        </p>
      )}
      <div className="dashboard-grid">
        <div className="dashboard-primary">
          {children}
          <div className="dashboard-secondary">
            <section
              className="panel"
              id="reports"
              aria-labelledby="reports-title"
            >
              <div className="panel-heading">
                <div className="panel-heading-label">
                  <Icon name="file" />
                  <h2 id="reports-title">RAPPORTS DISPONIBLES</h2>
                </div>
                <span>{reports.length}</span>
              </div>
              <div className="report-list">
                {reports.length ? (
                  reports.map((r) => (
                    <a key={r.url} href={r.url} download>
                      <Icon name="download" />
                      <span>
                        {r.label}
                        <small>{r.source} · Export archivé</small>
                      </span>
                      <Icon name="arrow" />
                    </a>
                  ))
                ) : (
                  <p className="empty-message">
                    Aucun rapport autorisé disponible
                    {loading ? " à ce stade de la lecture" : ""}.
                  </p>
                )}
              </div>
            </section>
            <section className="panel" aria-labelledby="tools-title">
              <div className="panel-heading">
                <div className="panel-heading-label">
                  <Icon name="terminal" />
                  <h2 id="tools-title">OUTILS ARCHIVÉS</h2>
                </div>
              </div>
              <div className="tool-list">
                {tools.length ? (
                  tools.map((t) => (
                    <div key={t}>
                      <Icon name="target" />
                      <strong>{t}</strong>
                      <Badge tone="blue">Exécution archivée</Badge>
                    </div>
                  ))
                ) : (
                  <p className="empty-message">Aucune exécution chargée.</p>
                )}
                <p>
                  Disponibilité actuelle des binaires non vérifiée. Aucun agent
                  autonome connecté.
                </p>
              </div>
            </section>
          </div>
        </div>
        <aside
          className="panel chat-placeholder"
          id="argos-chat"
          aria-labelledby="chat-title"
        >
          <div className="panel-heading">
            <div className="panel-heading-label">
              <Icon name="chat" />
              <h2 id="chat-title">ARGOS CHAT</h2>
            </div>
            <Badge>À venir</Badge>
          </div>
          <div className="chat-reserved">
            <div className="chat-orbit">
              <BrandLogo />
            </div>
            <h3>Votre futur assistant Argos</h3>
            <p>La conversation avec l’agent n’est pas encore disponible.</p>
            <p>
              Consultez les résultats vérifiés et leurs preuves depuis vos
              missions.
            </p>
            <a href="#missions">
              Explorer les missions <Icon name="arrow" />
            </a>
          </div>
          <div className="chat-inactive">
            <Icon name="lock" /> Chat indisponible <Icon name="send" />
          </div>
          <p className="chat-footnote">Aucune réponse IA simulée.</p>
        </aside>
        <section
          className="panel evidence-panel"
          id="evidence"
          aria-labelledby="evidence-title"
        >
          <div className="panel-heading">
            <div className="panel-heading-label">
              <Icon name="folder" />
              <h2 id="evidence-title">INDEX DES PREUVES</h2>
            </div>
            <span>Métadonnées archivées</span>
          </div>
          <div className="evidence-list">
            {evidence.map((e) => (
              <details key={e.id}>
                <summary>
                  <Icon name="shield" />
                  {e.tool}
                  <Badge
                    tone={e.verification === "verified" ? "green" : "amber"}
                  >
                    {e.verification === "verified"
                      ? "Preuve vérifiée"
                      : e.verification}
                  </Badge>
                  <time>{stamp(e.recorded_at)}</time>
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
            <p>
              {requests.length} reçu(s) HTTP chargé(s). Les empreintes,
              classifications et erreurs de chaque transaction sont consultables
              dans le détail des missions.
            </p>
            {!evidence.length && <p>Aucune preuve Nmap chargée.</p>}
            <p className="results-notice">
              Intégrité vérifiée à la lecture ; aucune signature d’authenticité
              indépendante. Les contenus HTTP et sorties brutes non archivés ne
              sont pas reconstitués.
            </p>
          </div>
        </section>
        <section
          className="panel events-panel"
          id="events"
          aria-labelledby="events-title"
        >
          <div className="panel-heading">
            <div className="panel-heading-label">
              <Icon name="terminal" />
              <h2 id="events-title">JOURNAL DES ARCHIVES</h2>
            </div>
            <span>
              <span className="archive-dot" /> Historique · Paris
            </span>
          </div>
          <p className="journal-note">
            Transactions et preuves horodatées, dédupliquées par identifiant.
            Aucun flux en direct. Les événements d’exécution non exposés par
            l’API ne sont pas inventés.
          </p>
          {events.length ? (
            <div
              className="results-scroll event-scroll"
              tabIndex={0}
              role="region"
              aria-label="Événements archivés"
            >
              <table className="event-table">
                <thead>
                  <tr>
                    <th>Horodatage</th>
                    <th>Source</th>
                    <th>Événement</th>
                    <th>Résultat</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id}>
                      <td>
                        <time>{stamp(e.time)}</time>
                      </td>
                      <td className="event-source">[{e.source}]</td>
                      <td>{e.label}</td>
                      <td className={e.error ? "event-error" : ""}>
                        {e.state}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="empty-message">Aucun événement archivé chargé.</p>
          )}
        </section>
      </div>
    </>
  );
}
