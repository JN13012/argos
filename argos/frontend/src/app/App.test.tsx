import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

vi.mock("../features/results/ResultsPanel", () => ({
  ResultsPanel: () => null,
}));

const healthyResponse = {
  ok: true,
  status: 200,
  json: async () => ({ status: "ok" }),
} as Response;

describe("ARGOS application shell", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(healthyResponse));
  });

  it("checks the API health endpoint and exposes only implemented navigation", async () => {
    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent(
      "API disponible",
    );
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/health",
      expect.objectContaining({ headers: { Accept: "application/json" } }),
    );
    expect(screen.getByRole("link", { name: "Dashboard" })).toHaveAttribute(
      "href",
      "#dashboard",
    );
    expect(screen.getByRole("link", { name: /^Missions$/ })).toHaveAttribute(
      "href",
      "#missions",
    );
    for (const label of ["Red Team", "OSINT", "Blue Team", "Agents"]) {
      expect(
        screen.getByRole("button", { name: `${label} · À venir` }),
      ).toBeDisabled();
    }
    expect(screen.queryByText("Jérémie")).not.toBeInTheDocument();
  });

  it("reports an unavailable API and allows a retry", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("Failed to fetch"))
      .mockResolvedValueOnce(healthyResponse);
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent(
      "API indisponible",
    );
    expect(screen.getByText(/Failed to fetch/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Réessayer" }));

    await waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent("API disponible"),
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects a successful HTTP response with an invalid health contract", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ...healthyResponse,
        json: async () => ({ status: "degraded" }),
      }),
    );
    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent(
      "API indisponible",
    );
    expect(
      screen.getByText(/ne respecte pas le contrat de santé/),
    ).toBeVisible();
  });
});
