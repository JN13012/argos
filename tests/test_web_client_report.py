"""Read-only CLI export of recorded web evidence."""

import json
import sqlite3
from uuid import UUID

import pytest
from argos.backend.attack.web.evidence_index import evidence_index
from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.attack.web.redirect_verification import RedirectVerification
from argos.backend.attack.web.report_coverage import coverage_rows
from argos.backend.attack.web.reporting import findings_export, render_markdown
from argos.cli import main

from test_web_browser_discovery import site as browser_site
from test_web_browser_runtime import mission as mission
from test_web_redirects import discover, site
from test_web_runtime import setup as setup


def test_report_keeps_confirmation_and_retest_after_runtime_closed(
    setup, capsys, tmp_path
):
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
    assert main([*args, "--format", "findings-json"]) == 0
    findings_text = capsys.readouterr().out
    findings = json.loads(findings_text)
    assert findings["schema_version"] == 1
    assert findings["mission_id"] == str(mid)
    assert findings["run_id"] == str(run_id)
    assert findings["configuration_sha256"] == saved["configuration_sha256"]
    [finding] = findings["findings"]
    assert finding["finding_id"] == initial["findings"][0]["id"]
    assert finding["family_id"] == "WEB-04"
    assert finding["status"] == "not_reproduced"
    assert finding["severity"] == "unrated"
    assert finding["remediation"]
    assert findings_export(initial)["findings"][0]["latest_retest"] is None
    for key, check in zip(
        ("first_confirmation", "latest_retest"), saved["redirect_checks"], strict=True
    ):
        assert finding[key] == {
            "check_id": check["id"],
            "recorded_at": check["recorded_at"],
            "verdict": check["verdict"],
            "receipts": [
                {"request_id": step["request_id"], "sha256": step["receipt_sha256"]}
                for step in check["steps"]
            ],
        }
    assert (
        "private-value" not in findings_text
        and "redirect-proof.invalid" not in findings_text
    )
    assert main([*args, "--format", "findings-json"]) == 0
    assert capsys.readouterr().out == findings_text
    before_path, after_path = tmp_path / "before.json", tmp_path / "after.json"
    before_path.write_text(json.dumps(findings_export(initial)), encoding="utf-8")
    after_path.write_text(findings_text, encoding="utf-8")
    assert (
        main(
            [
                "web",
                "compare-findings",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["changes"] == [
        {
            "finding_id": finding["finding_id"],
            "before": {"status": "confirmed", "latest_retest": None},
            "after": {
                "status": "not_reproduced",
                "latest_retest": {
                    "check_id": finding["latest_retest"]["check_id"],
                    "verdict": "not_confirmed",
                },
            },
        }
    ]
    assert main([*args, "--format", "coverage-json"]) == 0
    encoded = capsys.readouterr().out
    coverage = json.loads(encoded)
    assert coverage["schema_version"] == 1
    assert coverage["mission_id"] == str(mid)
    assert coverage["run_id"] == str(run_id)
    assert coverage["configuration_sha256"] == saved["configuration_sha256"]
    assert [row["family_id"] for row in coverage["families"]] == [
        f"WEB-{number:02d}" for number in range(1, 21)
    ]
    redirects = coverage["families"][3]
    assert redirects["status"] == "targeted_check_completed"
    assert redirects["counts"] == {
        "confirmed": 1,
        "not_reproduced": 1,
        "inconclusive": 0,
        "no_result": 0,
    }
    assert "private-value" not in encoded and "redirect-proof.invalid" not in encoded
    assert main([*args, "--format", "coverage-json"]) == 0
    assert capsys.readouterr().out == encoded
    assert main([*args, "--format", "evidence-json"]) == 0
    index_text = capsys.readouterr().out
    index = json.loads(index_text)
    assert index["schema_version"] == 1 and index["run_id"] == str(run_id)
    assert index["mission_id"] == str(mid)
    assert index["configuration_sha256"] == saved["configuration_sha256"]
    receipts = {item["request_id"]: item for item in index["receipts"]}
    for check in saved["redirect_checks"]:
        for step in check["steps"]:
            assert receipts[step["request_id"]]["sha256"] == step["receipt_sha256"]
            assert receipts[step["request_id"]]["references"] == [
                {"kind": "redirect_check", "id": check["id"]}
            ]
    assert any(
        ref["kind"] == "route"
        for item in receipts.values()
        for ref in item["references"]
    )
    assert (
        "private-value" not in index_text and "redirect-proof.invalid" not in index_text
    )
    assert main([*args, "--format", "evidence-json"]) == 0
    assert capsys.readouterr().out == index_text
    proof = next(
        value
        for value in receipts.values()
        if value["references"][0]["kind"] == "redirect_check"
    )
    lookup = [
        "web",
        "evidence",
        "--run-id",
        str(run_id),
        "--db",
        str(runtime.database),
    ]
    selected = [*lookup, "--request-id", proof["request_id"], "--expected-sha256"]
    assert main([*selected, proof["sha256"]]) == 0
    detail_text = capsys.readouterr().out
    detail = json.loads(detail_text)
    assert detail["request_id"] == proof["request_id"]
    assert detail["sha256"] == proof["sha256"]
    assert detail["references"] == proof["references"]
    assert detail["state"] == "completed" and detail["error"] is None
    assert set(detail["response"]) == {"status", "body_complete"}
    assert (
        "private-value" not in detail_text
        and "redirect-proof.invalid" not in detail_text
    )
    assert main([*selected, "0" * 64]) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "storage_failed"}
    assert main([*lookup, "--request-id", str(UUID(int=0))]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
    assert runtime.database.read_bytes() == original_db
    assert (len(worker.calls), len(resolver.calls)) == calls


def test_partial_report_keeps_api_observation_distinct_from_testing(mission, capsys):
    m = mission(browser={"max_navigations": 1})
    saved = browser_site(m).run(m.run_id)
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
                "coverage-json",
            ]
        )
        == 0
    )
    encoded = capsys.readouterr().out
    rows = {row["family_id"]: row for row in json.loads(encoded)["families"]}
    assert rows["WEB-02"]["status"] == "observed"
    assert rows["WEB-02"]["counts"]["api_observations"] == 1
    assert rows["WEB-15"]["status"] == "not_tested"
    assert "private-canary" not in encoded
    index = evidence_index(saved)
    api = saved["browser"]["observed_apis"][0]
    receipt = next(
        item for item in index["receipts"] if item["request_id"] == api["request_id"]
    )
    assert receipt["sha256"] == api["receipt_sha256"]
    assert receipt["references"] == [{"kind": "navigation", "id": api["navigation_id"]}]
    assert findings_export(saved)["findings"] == []


def test_findings_export_can_trace_a_first_confirmation_to_a_retest(setup):
    runtime, mid, worker, _, _ = setup()
    site(worker, "fixed")
    with runtime:
        run_id = discover(runtime, mid)
        original = RedirectVerification(runtime).run(run_id)
        check_id = original["redirect_checks"][0]["id"]
        site(worker)
        saved = RedirectVerification(runtime).run(run_id, retest=UUID(check_id))

    [finding] = findings_export(saved)["findings"]
    assert findings_export(original)["findings"] == []
    assert finding["finding_id"] == check_id
    assert finding["status"] == "confirmed"
    assert finding["first_confirmation"] == finding["latest_retest"]
    assert (
        finding["first_confirmation"]["check_id"] == saved["redirect_checks"][1]["id"]
    )


def test_evidence_index_deduplicates_references_and_rejects_conflicts():
    request = str(UUID(int=1))
    route_id = str(UUID(int=2))
    navigation_id = str(UUID(int=3))
    route = dict(id=route_id, request_id=request, evidence_sha256="a" * 64)
    resource = dict(request_id=request, receipt_sha256="a" * 64)
    report = dict(
        mission_id=str(UUID(int=4)),
        run_id=str(UUID(int=5)),
        configuration_sha256="b" * 64,
        surface=[route, dict(id=str(UUID(int=6)), request_id=str(UUID(int=7)))],
        browser=dict(
            navigation_details=[
                dict(navigation_id=navigation_id, resources=[resource, resource])
            ]
        ),
        redirect_checks=[],
    )
    assert evidence_index(report)["receipts"] == [
        dict(
            request_id=request,
            sha256="a" * 64,
            references=[
                {"kind": "navigation", "id": navigation_id},
                {"kind": "route", "id": route_id},
            ],
        )
    ]
    resource["receipt_sha256"] = "c" * 64
    with pytest.raises(WebIntegrityError, match="Conflicting receipt fingerprints"):
        evidence_index(report)


def test_verify_saved_evidence_rejects_changed_export_and_database(
    mission, tmp_path, capsys
):
    m = mission(browser={"max_navigations": 1})
    browser_site(m).run(m.run_id)
    scope = ["--run-id", str(m.run_id), "--db", str(m.path)]
    assert main(["web", "report", *scope, "--format", "evidence-json"]) == 0
    original = capsys.readouterr().out
    index_file = tmp_path / "index.json"
    index_file.write_text(original, encoding="utf-8")
    verify = ["web", "verify-evidence", *scope, "--index", str(index_file)]
    original_db = m.path.read_bytes()
    saved = json.loads(original)
    assert main(verify) == 0
    assert json.loads(capsys.readouterr().out) == {
        key: value for key, value in saved.items() if key != "receipts"
    } | {"verified_receipts": len(saved["receipts"])}
    assert index_file.read_text(encoding="utf-8") == original

    index_file.write_text('{"schema_version": 1, ' + original[1:], encoding="utf-8")
    assert main(verify) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}

    receipt = next(
        item
        for item in saved["receipts"]
        if item["references"][0]["kind"] == "navigation"
    )
    receipt["sha256"] = "0" * 64
    index_file.write_text(json.dumps(saved), encoding="utf-8")
    assert main(verify) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "index_mismatch"}

    saved["receipts"].remove(receipt)
    index_file.write_text(json.dumps(saved), encoding="utf-8")
    assert main(verify) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "index_mismatch"}
    assert m.path.read_bytes() == original_db

    index_file.write_text(original, encoding="utf-8")
    with sqlite3.connect(m.path) as db:
        assert (
            db.execute(
                "UPDATE web_http_evidence SET payload_sha256=? WHERE request_id=?",
                ("0" * 64, receipt["request_id"]),
            ).rowcount
            == 1
        )
    assert main(verify) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "storage_failed"}


def test_verify_report_checks_all_saved_exports_without_writing(
    mission, tmp_path, capsys
):
    m = mission(browser={"max_navigations": 1})
    browser_site(m).run(m.run_id)
    scope = ["--run-id", str(m.run_id), "--db", str(m.path)]
    verify = ["web", "verify-report", *scope]
    files = {}
    for flag, name in (
        ("--coverage", "coverage-json"),
        ("--index", "evidence-json"),
        ("--findings", "findings-json"),
    ):
        assert main(["web", "report", *scope, "--format", name]) == 0
        path = tmp_path / f"{name}.json"
        payload = json.loads(capsys.readouterr().out)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        files[name] = (path, payload)
        verify.extend((flag, str(path)))

    original_db = m.path.read_bytes()
    originals = {name: path.read_bytes() for name, (path, _) in files.items()}
    assert main(verify) == 0
    assert json.loads(capsys.readouterr().out) == {
        key: value
        for key, value in files["coverage-json"][1].items()
        if key != "families"
    } | {"verified_formats": list(files)}
    assert {name: path.read_bytes() for name, (path, _) in files.items()} == originals

    coverage_path, coverage = files["coverage-json"]
    index_path, index = files["evidence-json"]
    findings_path, findings = files["findings-json"]
    findings_path.write_text(
        json.dumps(findings | {"schema_version": True}), encoding="utf-8"
    )
    index_path.write_text(json.dumps(index | {"receipts": []}), encoding="utf-8")
    assert main(verify) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": "report_mismatch",
        "mismatches": ["evidence-json", "findings-json"],
    }
    coverage_path.write_text(json.dumps(coverage | {"families": []}), encoding="utf-8")
    assert main(verify) == 1
    assert json.loads(capsys.readouterr().out)["mismatches"] == list(files)
    coverage_path.write_text(
        '{"schema_version": 1, "schema_version": 1}', encoding="utf-8"
    )
    assert main(verify) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
    coverage_path.write_text('{"schema_version": NaN}', encoding="utf-8")
    assert main(verify) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
    assert m.path.read_bytes() == original_db


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ([], "not_tested"),
        (["not_tested"], "not_tested"),
        (["inconclusive"], "inconclusive"),
        (["not_confirmed", "inconclusive"], "partial"),
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
    assert rows[0]["status"] == "not_observed"  # A control request alone isn't a page.
    assert rows[3]["status"] == expected


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
    assert main([*args, "--format", "coverage-json"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
    assert main([*args, "--format", "findings-json"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
    with pytest.raises(SystemExit) as error:
        main([*args, "--format", "markdown", "--json"])
    assert error.value.code == 2
