import { expect, test } from "@playwright/test";

test("shows the SOC shell and verifies the local API", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));

  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Bienvenue sur ARGOS" }),
  ).toBeVisible();
  await expect(page.getByRole("status")).toHaveText("API disponible");
  if (test.info().project.name === "mobile")
    await page.getByRole("button", { name: "Ouvrir la navigation" }).click();
  const navigation = page.getByRole("navigation", { name: "Espaces Argos" });
  await expect(
    navigation.getByRole("link", { name: "Dashboard" }),
  ).toHaveAttribute("aria-current", "location");
  for (const domain of ["Red Team", "OSINT", "Blue Team", "Agents"]) {
    await expect(
      navigation.getByRole("button", { name: `${domain} · À venir` }),
    ).toBeDisabled();
  }
  await navigation.getByRole("link", { name: "Rapports" }).click();
  await expect(page).toHaveURL(/#reports$/);
  await expect(
    page.getByRole("heading", { name: "RAPPORTS DISPONIBLES" }),
  ).toBeVisible();
  await expect(page.getByText("Aucune réponse IA simulée.")).toBeAttached();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
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
  const search = page.getByRole("searchbox", {
    name: "Rechercher une mission ou une cible",
  });
  await search.fill("absent");
  await expect(
    page.getByText("Aucune mission ne correspond à la recherche."),
  ).toBeVisible();
  await search.fill("archivée");
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
