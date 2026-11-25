"""Local CLI memory commands never accept a user impersonation parameter."""

import json

from argos.cli import main

from test_mission_review import archived as archived
from test_review_memory import captured as captured
from test_web_runtime import setup as setup


def test_memory_cli_capture_query_context_and_logical_delete(
    captured, tmp_path, capsys
):
    memory, db, mid, journal, rid, _ = captured
    scope = ["--memory-root", str(memory.root), "--mission-id", str(mid)]
    assert (
        main(
            [
                "review",
                "memory-capture",
                *scope,
                "--db",
                str(db),
                "--journal",
                str(journal),
                "--review-id",
                str(rid),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["added_records"] == 0
    assert main(["review", "memory-info", *scope]) == 0
    assert json.loads(capsys.readouterr().out)["uid"] == memory.uid
    assert (
        main(
            [
                "review",
                "memory-search",
                *scope,
                "--query",
                "status 404",
                "--origin",
                "verified_archive",
            ]
        )
        == 0
    )
    row = json.loads(capsys.readouterr().out)["items"][0]
    assert main(["review", "memory-get", *scope, "--entry-id", row["id"]]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == row["id"]
    assert main(["review", "summary", *scope, "--db", str(db)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["memory_context"]["data_only"] is True
    assert main(["review", "memory-focus", *scope, "--review-id", str(rid)]) == 0
    capsys.readouterr()
    note = tmp_path / "reason.json"
    note.write_text('{"reason":"Suppression explicite"}')
    note.chmod(0o600)
    assert (
        main(
            [
                "review",
                "memory-delete",
                *scope,
                "--entry-id",
                row["id"],
                "--input",
                str(note),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["review", "memory-get", *scope, "--entry-id", row["id"]]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "review_invalid_input"
    assert main(["review", "memory-info", *scope, "--expected-head", "0" * 64]) == 1
    capsys.readouterr()
