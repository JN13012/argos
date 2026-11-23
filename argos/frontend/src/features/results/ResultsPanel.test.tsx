import {
  fireEvent,
  render,
  screen,
  within,
  waitFor,
} from "@testing-library/react";
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
      await within(screen.getByRole("dialog")).findByRole("cell", {
        name: /GET http:\/\/127.0.0.1:3087\/api\/Products/,
      }),
    ).toBeVisible();
    expect(
      screen.getByText("Réponse confirmée, contenu non exploré"),
    ).toBeVisible();
    expect(screen.getByRole("cell", { name: /Wordlist ciblée/ })).toBeVisible();
    expect(screen.getByText("Corps HTTP non archivé.")).toBeVisible();
    expect(
      within(screen.getByRole("dialog")).getByRole("link", {
        name: "Rapport HTML",
      }),
    ).toHaveAttribute("href", "/api/v1/results/lab/reports/html");
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
    expect(
      await within(screen.getByRole("dialog")).findByRole("alert"),
    ).toHaveTextContent("La vérification des preuves a échoué");
    expect(
      screen.queryByRole("cell", {
        name: /GET http:\/\/127.0.0.1:3087\/api\/Products/,
      }),
    ).not.toBeInTheDocument();
  });
  it("filters missions without changing archive statistics and does not simulate chat", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(response(sources))
        .mockResolvedValueOnce(response(detail)),
    );
    const { rerender } = render(<ResultsPanel />);
    await screen.findByRole("button", { name: "Ouvrir la mission web" });
    await waitFor(() =>
      expect(screen.getByText(/1 \/ 1 missions relues/)).toBeVisible(),
    );
    rerender(<ResultsPanel query="does-not-match" />);
    expect(
      screen.queryByRole("button", { name: "Ouvrir la mission web" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("Aucune mission ne correspond à la recherche."),
    ).toBeVisible();
    expect(screen.getByText(/1 \/ 1 missions relues/)).toBeVisible();
    expect(screen.getByText("Aucune réponse IA simulée.")).toBeVisible();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    rerender(<ResultsPanel query="3087" />);
    expect(
      screen.getByRole("button", { name: "Ouvrir la mission web" }),
    ).toBeVisible();
  });
  it("deduplicates receipts shared by network and web missions", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          response({
            sources: [
              {
                ...sources.sources[0],
                missions: [mission, { ...mission, id: "other" }],
              },
            ],
          }),
        )
        .mockResolvedValue(response(detail)),
    );
    render(<ResultsPanel />);
    await screen.findByText(/2 \/ 2 missions relues/);
    expect(
      screen.getByText(
        "1 reçu(s) HTTP chargé(s). Les empreintes, classifications et erreurs de chaque transaction sont consultables dans le détail des missions.",
      ),
    ).toBeVisible();
    expect(
      within(
        screen.getByRole("region", { name: "Événements archivés" }),
      ).getAllByRole("row"),
    ).toHaveLength(2);
  });
  it("reports unavailable sources and catalog failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        response({
          sources: [
            { ...sources.sources[0], state: "unavailable", missions: [] },
          ],
        }),
      ),
    );
    const { unmount } = render(<ResultsPanel />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Source indisponible",
    );
    unmount();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    render(<ResultsPanel />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Impossible de charger les missions",
    );
  });
  it("bounds background reads and aborts pending requests on unmount", async () => {
    const signals: AbortSignal[] = [];
    const fetchMock = vi
      .fn()
      .mockImplementation((url: string, options: RequestInit) => {
        if (url === "/api/v1/results")
          return Promise.resolve(
            response({
              sources: [
                {
                  ...sources.sources[0],
                  missions: Array.from({ length: 6 }, (_, i) => ({
                    ...mission,
                    id: `mission-${i}`,
                  })),
                },
              ],
            }),
          );
        signals.push(options.signal as AbortSignal);
        return new Promise(() => {});
      });
    vi.stubGlobal("fetch", fetchMock);
    const { unmount } = render(<ResultsPanel />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(5));
    expect(signals).toHaveLength(4);
    unmount();
    expect(signals.every((signal) => signal.aborted)).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(5);
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
