"""Compare coverage exports without access to a mission database."""

import json
from pathlib import Path
from uuid import UUID

import pytest
from argos.backend.attack.web.report_coverage import coverage_export
from argos.cli import main


@pytest.fixture
def snapshots(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report: dict = dict(
        mission_id=str(UUID(int=1)),
        run_id=str(UUID(int=2)),
        configuration_sha256="e" * 64,
        surface=[],
        browser=dict(observed_apis=[], observed_links=[]),
        redirect_checks=[{"verdict": "confirmed"}],
    )
    before = coverage_export(report)
    report["browser"]["observed_apis"].append({})
    report["redirect_checks"].append({"verdict": "not_confirmed"})
    after = coverage_export(report)
    Path("before.json").write_text(json.dumps(before), encoding="utf-8")
    Path("after.json").write_text(json.dumps(after), encoding="utf-8")
    return ["web", "compare-coverage", "--before", "before.json", "--after"], after


def test_cli_compares_only_changed_states_and_counts(snapshots, capsys):
    options, after = snapshots
    # Display text does not participate in the comparison or appear in output.
    after["families"][0]["detail"] = "private-marker"
    Path("after.json").write_text(json.dumps(after), encoding="utf-8")
    original = {file: file.read_bytes() for file in Path.cwd().iterdir()}

    assert main([*options, "after.json"]) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["run_id"] == after["run_id"]
    assert result["changes"] == [
        dict(
            family_id="WEB-02",
            status_before="not_observed",
            status_after="observed",
            counts={"api_observations": {"before": 0, "after": 1}},
        ),
        dict(
            family_id="WEB-04",
            status_before="targeted_check_completed",
            status_after="targeted_check_completed",
            counts={"not_reproduced": {"before": 0, "after": 1}},
        ),
    ]
    assert "private-marker" not in output
    assert main([*options, "before.json"]) == 0
    assert json.loads(capsys.readouterr().out)["changes"] == []
    assert {file: file.read_bytes() for file in Path.cwd().iterdir()} == original


@pytest.mark.parametrize("key", ["mission_id", "run_id", "configuration_sha256"])
def test_cli_rejects_unrelated_snapshots(snapshots, capsys, key):
    options, after = snapshots
    after[key] = "a" * 64 if key.endswith("sha256") else str(UUID(int=9))
    Path("after.json").write_text(json.dumps(after), encoding="utf-8")
    assert main([*options, "after.json"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}


@pytest.mark.parametrize("fault", ["version", "duplicate", "missing", "boolean"])
def test_cli_rejects_invalid_snapshot(snapshots, capsys, fault):
    options, after = snapshots
    if fault == "version":
        after["schema_version"] = 2
    elif fault == "missing":
        after["families"].pop()
    elif fault == "boolean":
        after["families"][1]["counts"]["api_observations"] = True
    data = json.dumps(after)
    if fault == "duplicate":
        data = '{"schema_version": 1, ' + data[1:]
    Path("after.json").write_text(data, encoding="utf-8")
    assert main([*options, "after.json"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
