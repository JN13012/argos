import { expect, test } from "@playwright/test";

test("shows the minimal home and verifies the local API", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));

  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Bienvenue sur ARGOS" }),
  ).toBeVisible();
  await expect(page.getByRole("status")).toHaveText("API disponible");
  await expect(
    page.getByRole("link", { name: "Accueil", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  for (const domain of ["ATTACK", "INTEL", "DEFEND"]) {
    await expect(page.getByText(`${domain} · à venir`)).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  }
  expect(errors).toEqual([]);
});

test("opens archived results with explicit classifications and closes with Escape", async ({
  page,
}) => {
  const mission = {
    id: "00000000-0000-4000-8000-000000000001",
    title: "Mission archivée",
    state: "revoked",
    kind: "web",
    targets: ["http://target.invalid/"],
  };
  await page.route("**/api/v1/results", (route) =>
    route.fulfill({
      json: {
        sources: [
          {
            id: "lab",
            label: "Source autorisée",
            state: "available",
            missions: [mission],
          },
        ],
      },
    }),
  );
  await page.route("**/api/v1/results/lab/missions/*", (route) =>
    route.fulfill({
      json: {
        ...mission,
        runs: [{ status: "partial" }],
        tools: [],
        ports: [],
        routes: [],
        requests: [
          {
            id: "request",
            url: "http://target.invalid/missing",
            method: "GET",
            tool: "ffuf",
            http_status: 200,
            state: "completed",
            classification: "spa_generic",
            reason: "suspected_soft_404",
            error: null,
            wordlist_provenance: "targeted",
            confidence: "observed_response",
            evidence_sha256: "0".repeat(64),
            verification: "verified",
            recorded_at: null,
          },
        ],
        evidence: [],
        technologies: [],
        limitations: ["Corps non archivés."],
        reports: [],
        wordlist_provenance: "targeted",
        duration_seconds: null,
        started_at: null,
        finished_at: null,
      },
    }),
  );
  await page.goto("/");
  const open = page.getByRole("button", { name: "Ouvrir la mission web" });
  await open.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByText("SPA générique suspectée", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("cell", { name: /Wordlist ciblée/ }),
  ).toBeVisible();
  await dialog.getByText("Reçu vérifié", { exact: true }).click();
  await expect(
    dialog.getByText("UUID : request", { exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(open).toBeFocused();
});
