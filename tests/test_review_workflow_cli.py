"""The CLI keeps private inputs out of arguments and hides raw snapshots by default."""

import json
from uuid import UUID

from argos.backend.attack.review.workflow import read_workflow
from argos.cli import main

from test_mission_review import archived as archived
from test_operator_journal import operator_input
from test_review_workflow import Model
from test_web_runtime import setup as setup


def test_cli_review_cycle(archived, tmp_path, capsys, monkeypatch):
    db, mid, *_ = archived
    journal = tmp_path / "operator.sqlite"
    common = ["--journal", str(journal)]
    assert (
        main(
            [
                "review",
                "workflow-start",
                *common,
                "--db",
                str(db),
                "--mission-id",
                str(mid),
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert "events" not in created
    assert created["state"] == "created"
    rid = created["review_id"]
    common += ["--review-id", rid]
    monkeypatch.setattr(
        "argos.backend.attack.review.cli.OllamaProvider", lambda *args: Model()
    )
    assert (
        main(
            [
                "review",
                "workflow-analyze",
                *common,
                "--db",
                str(db),
                "--model",
                "fixture:1",
            ]
        )
        == 0
    )
    ready = json.loads(capsys.readouterr().out)
    assert ready["state"] == "ready"
    note = tmp_path / "note.json"
    note.write_text(json.dumps({"operator": "local", "note": "Observations revues"}))
    note.chmod(0o600)
    assert main(["review", "workflow-annotate", *common, "--input", str(note)]) == 0
    capsys.readouterr()
    private = read_workflow(journal, UUID(rid))
    decision = operator_input(private["events"][0]["data"]["snapshot"])
    note.write_text(json.dumps(decision))
    assert (
        main(
            [
                "review",
                "workflow-accept",
                *common,
                "--db",
                str(db),
                "--input",
                str(note),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "accepted" and result["execution_authorized"] is False
    assert (
        main(
            [
                "review",
                "workflow-show",
                *common,
                "--expected-head",
                result["head_sha256"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == result
    assert main(["review", "workflow-show", *common, "--history"]) == 0
    assert json.loads(capsys.readouterr().out)["events"]
    assert main(["review", "workflow-show", *common, "--expected-head", "0" * 64]) == 1
    assert (
        json.loads(capsys.readouterr().out)["error"]
        == "review_integrity_or_storage_failed"
    )
