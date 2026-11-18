"""Offline comparison of finding states and latest rechecks."""

import json
from uuid import UUID

import pytest
from argos.cli import main


@pytest.fixture
def exports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    finding = dict(
        finding_id=str(UUID(int=3)),
        status="retest_inconclusive",
        latest_retest={"check_id": str(UUID(int=4)), "verdict": "inconclusive"},
    )
    snapshot = dict(
        schema_version=1,
        mission_id=str(UUID(int=1)),
        run_id=str(UUID(int=2)),
        configuration_sha256="a" * 64,
        findings=[finding],
    )
    before.write_text(json.dumps(snapshot), encoding="utf-8")
    return (
        ["web", "compare-findings", "--before", str(before), "--after"],
        before,
        after,
        snapshot,
    )


def test_compares_rechecks_with_same_status_and_presence(exports, capsys):
    options, before, after, snapshot = exports
    finding = snapshot["findings"][0]
    finding["latest_retest"]["check_id"] = str(UUID(int=5))
    finding["remediation"] = "private-text"
    added = str(UUID(int=6))
    snapshot["findings"].append(
        dict(finding_id=added, status="confirmed", latest_retest=None)
    )
    after.write_text(json.dumps(snapshot), encoding="utf-8")
    files = {file: file.read_bytes() for file in (before, after)}
    assert main([*options, str(after)]) == 0
    output = capsys.readouterr().out
    first, second = json.loads(output)["changes"]
    assert first["finding_id"] == finding["finding_id"]
    assert (
        first["before"]["status"] == first["after"]["status"] == "retest_inconclusive"
    )
    assert first["before"]["latest_retest"]["check_id"] == str(UUID(int=4))
    assert first["after"]["latest_retest"]["check_id"] == str(UUID(int=5))
    assert second["finding_id"] == added
    assert second["before"] is None and second["after"]["status"] == "confirmed"
    assert "private-text" not in output
    assert (
        main(
            ["web", "compare-findings", "--before", str(after), "--after", str(before)]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["changes"][1]["after"] is None
    assert main([*options, str(before)]) == 0
    assert json.loads(capsys.readouterr().out)["changes"] == []
    assert {file: file.read_bytes() for file in (before, after)} == files


@pytest.mark.parametrize("fault", ["identity", "duplicate", "status", "verdict"])
def test_rejects_incompatible_or_invalid_comparison(exports, capsys, fault):
    options, _, after, snapshot = exports
    finding = snapshot["findings"][0]
    if fault == "identity":
        snapshot["run_id"] = str(UUID(int=6))
    elif fault == "duplicate":
        snapshot["findings"].append(finding)
    elif fault == "status":
        finding["status"] = "confirmed"
    else:
        finding["latest_retest"]["verdict"] = "private-text"
    after.write_text(json.dumps(snapshot), encoding="utf-8")
    assert main([*options, str(after)]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
