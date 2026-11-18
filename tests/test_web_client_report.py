"""Read-only CLI export of recorded web evidence."""

import json
from uuid import UUID

import pytest
from argos.backend.attack.web.redirect_verification import RedirectVerification
from argos.backend.attack.web.report_coverage import coverage_rows
from argos.backend.attack.web.reporting import render_markdown
from argos.cli import main

from test_web_browser_discovery import site as browser_site
from test_web_browser_runtime import mission as mission
from test_web_redirects import discover, site
from test_web_runtime import setup as setup


def test_report_keeps_confirmation_and_retest_after_runtime_closed(setup, capsys):
    runtime, mid, worker, resolver, _ = setup()
    site(worker)
    with runtime:
        run_id = discover(runtime, mid)
        initial = RedirectVerification(runtime).run(run_id)
        site(worker, "fixed")
        saved = RedirectVerification(runtime).run(
            run_id, retest=UUID(initial["findings"][0]["id"])
        )

    args = ["web", "report", "--run-id", str(run_id), "--db", str(runtime.database)]
    original_db = runtime.database.read_bytes()
    calls = len(worker.calls), len(resolver.calls)
    assert main([*args, "--format", "markdown"]) == 0
    result = capsys.readouterr().out
    assert "Non reproduit au dernier recontrôle" in result
    assert "Première confirmation" in result
    assert "| WEB-04 | Redirections et navigation | Contrôle ciblé effectué |" in result
    assert "1 confirmé(s), 1 non reproduit(s)" in result
    for check in saved["redirect_checks"]:
        assert check["id"] in result
        for step in check["steps"]:
            assert step["receipt_sha256"] in result
    assert "private-value" not in result and "redirect-proof.invalid" not in result
    assert main([*args, "--format", "markdown"]) == 0
    assert capsys.readouterr().out == result
    assert main([*args, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == saved
    assert runtime.database.read_bytes() == original_db
    assert (len(worker.calls), len(resolver.calls)) == calls


def test_partial_report_keeps_api_observation_distinct_from_testing(mission, capsys):
    m = mission(browser={"max_navigations": 1})
    browser_site(m).run(m.run_id)
    assert (
        main(
            [
                "web",
                "report",
                "--run-id",
                str(m.run_id),
                "--db",
                str(m.path),
                "--format",
                "markdown",
            ]
        )
        == 0
    )
    result = capsys.readouterr().out
    assert "`partial` (`budget_exhausted`)" in result
    assert "Appels API observés : 1" in result
    assert "L’observation ne valide aucun contrôle" in result
    assert "Aucun constat confirmé" in result
    assert "private-canary" not in result
    assert "| WEB-02 | SPA et API observées dans le navigateur | Observé |" in result
    assert "| WEB-07 | Contrôle d’accès | Non testé |" in result
    assert "| WEB-15 | Contrôles de sécurité des API REST | Non testé |" in result


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ([], "Non testé"),
        (["not_tested"], "Non testé"),
        (["inconclusive"], "Inconclusif"),
        (["not_confirmed", "inconclusive"], "Partiel"),
    ],
)
def test_coverage_distinguishes_missing_and_incomplete_checks(verdicts, expected):
    rows = coverage_rows(
        {
            "surface": [{"kind": "probe", "request_state": "completed"}],
            "browser": {"observed_apis": [], "observed_links": []},
            "redirect_checks": [{"verdict": verdict} for verdict in verdicts],
        }
    )
    assert len(rows) == 20
    assert rows[0][2] == "Non observé"  # A control request alone isn't a page.
    assert rows[3][2] == expected


def test_report_discards_unknown_text_including_markdown_and_html(mission):
    m = mission()
    report = browser_site(m).run(m.run_id)
    hostile = "`\n![private-canary](https://example.invalid/tracker)<img>"
    report["reason"] = hostile
    report["reasons"][hostile] = 1
    report["surface"][0]["observations"] = {"arbitrary": hostile}
    rendered = render_markdown(report)
    assert "Non classé" in rendered
    assert all(
        value not in rendered
        for value in ("private-canary", "example.invalid", "<img>")
    )


def test_report_format_constraints(setup, capsys):
    runtime, mid, *_ = setup()
    runtime.close()
    args = ["web", "report", "--mission-id", str(mid), "--db", str(runtime.database)]
    assert main([*args, "--format", "markdown"]) == 2
    assert "invalid_input" in capsys.readouterr().out
    with pytest.raises(SystemExit) as error:
        main([*args, "--format", "markdown", "--json"])
    assert error.value.code == 2
