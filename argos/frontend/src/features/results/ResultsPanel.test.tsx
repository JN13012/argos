import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ResultsPanel } from "./ResultsPanel";

const mission = {
  id: "mission",
  title: "Juice Shop réel",
  state: "revoked",
  kind: "web",
  targets: ["http://127.0.0.1:3087/"],
};
const sources = {
  sources: [
    {
      id: "lab",
      label: "Juice Shop ciblé",
      state: "available",
      missions: [mission],
    },
  ],
};
const detail = {
  ...mission,
  runs: [{ id: "run", status: "partial" }],
  tools: [{ tool: "ffuf", state: "completed", exit_code: 0 }],
  ports: [],
  routes: [],
  requests: [
    {
      id: "receipt",
      url: "http://127.0.0.1:3087/api/Products",
      method: "GET",
      tool: "ffuf",
      http_status: 200,
      state: "completed",
      classification: "response_observed",
      reason: "non_html",
      error: null,
      wordlist_provenance: "targeted",
      confidence: "observed_response",
      evidence_sha256: "abc",
      verification: "verified",
      recorded_at: "2026-11-23T16:44:58Z",
    },
  ],
  evidence: [],
  technologies: [],
  limitations: ["Corps HTTP non archivé."],
  verification: "verified",
  started_at: null,
  finished_at: null,
  duration_seconds: null,
  reports: [
    {
      id: "html",
      label: "Rapport HTML",
      url: "/api/v1/results/lab/reports/html",
    },
  ],
  wordlist_provenance: "targeted",
};
function response(value: unknown) {
  return { ok: true, json: async () => value };
}

describe("Real result consultation", () => {
  it("loads a real mission and distinguishes targeted observations from findings", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(response(sources))
        .mockResolvedValueOnce(response(detail)),
    );
    render(<ResultsPanel />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Ouvrir la mission web" }),
    );
    expect(
      await screen.findByRole("cell", {
        name: /GET http:\/\/127.0.0.1:3087\/api\/Products/,
      }),
    ).toBeVisible();
    expect(
      screen.getByText("Réponse confirmée, contenu non exploré"),
    ).toBeVisible();
    expect(screen.getByRole("cell", { name: /Wordlist ciblée/ })).toBeVisible();
    expect(screen.getByText("Corps HTTP non archivé.")).toBeVisible();
    expect(screen.getByRole("link", { name: "Rapport HTML" })).toHaveAttribute(
      "href",
      "/api/v1/results/lab/reports/html",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Fermer les résultats" }),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
  it("shows verification errors without stale results", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(response(sources))
        .mockResolvedValueOnce({ ok: false, status: 409 }),
    );
    render(<ResultsPanel />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Ouvrir la mission web" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "La vérification des preuves a échoué",
    );
    expect(
      screen.queryByRole("cell", {
        name: /GET http:\/\/127.0.0.1:3087\/api\/Products/,
      }),
    ).not.toBeInTheDocument();
  });
  it("handles unconfigured sources", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(response({ sources: [] })),
    );
    render(<ResultsPanel />);
    expect(await screen.findByText(/Aucune source configurée/)).toBeVisible();
  });
});
