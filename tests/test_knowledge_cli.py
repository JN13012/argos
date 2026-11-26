import json
from uuid import uuid4

from argos.cli import main


def test_cli_document_lifecycle_from_custom_root(tmp_path, monkeypatch, capsys):
    root = tmp_path / "data"
    monkeypatch.setenv("ARGOS_DATA_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "guide.md").write_text("# Guide\n\n![[private]]\n", encoding="utf-8")

    def run(*args):
        assert main(["knowledge", *args]) == 0
        return json.loads(capsys.readouterr().out)

    assert run("init")["status"] == "initialized"
    assert (
        run(
            "source-register",
            "local",
            "--publisher",
            "Local",
            "--origin",
            "notes:local",
            "--rights",
            "Private",
        )["status"]
        == "pending"
    )
    imported = run(
        "import",
        "guide.md",
        "local",
        "guide",
        "--title",
        "Guide",
        "--origin",
        "notes:guide",
        "--tag",
        "domain=web-api",
        "--strategy",
        "structural",
        "--size",
        "64",
        "--overlap",
        "8",
    )
    version = imported["version"]["id"]
    assert imported["fragment_count"] == 1
    assert imported["version"]["metadata"]["tags"] == [
        {"dimension": "domain", "value": "web-api"}
    ]
    assert run("versions", "local", "guide")[0]["id"] == version
    assert (
        run("inspect", "local", "guide", version, "--normalized")["normalized"]["text"]
        == "# Guide\n\n![[private]]\n"
    )
    fragment_args = [
        "fragments",
        "local",
        "guide",
        version,
        "--strategy",
        "structural",
        "--size",
        "64",
        "--overlap",
        "8",
    ]
    assert main(["knowledge", *fragment_args]) == 1
    assert main(["knowledge", "show", "local", "guide"]) == 1
    assert main(["knowledge", "approve", "local", "guide", version]) == 1
    assert capsys.readouterr().out == ""
    assert run(*fragment_args, "--retained")[0]["citations"][-1]["line_start"] == 3
    assert run("source-approve", "local")["status"] == "approved"
    assert run("approve", "local", "guide", version)["status"] == "approved"
    assert run("show", "local", "guide", "--normalized")["id"] == version
    assert run(*fragment_args, "--limit", "1")[0]["ordinal"] == 0
    assert not run(*fragment_args, "--offset", "1")
    assert run("withdraw", "local", "guide")["status"] == "withdrawn"
    assert main(["knowledge", *fragment_args]) == 1
    capsys.readouterr()
    assert run(*fragment_args, "--retained")
    assert run("source-withdraw", "local")["status"] == "withdrawn"
    assert len(list(root.rglob("*.sqlite3"))) == 1


def test_cli_collection_scope_is_explicit(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    assert main(["knowledge", "--collection", "mission", "init"]) == 1
    assert (
        main(
            [
                "knowledge",
                "--collection",
                "organization",
                "--scope-id",
                str(uuid4()),
                "init",
            ]
        )
        == 1
    )
    assert "Error:" in capsys.readouterr().err
    assert not (tmp_path / "data").exists()
    scope = uuid4()
    assert (
        main(["knowledge", "--collection", "mission", "--scope-id", str(scope), "init"])
        == 0
    )
    assert f"mission-{scope}" in next(tmp_path.rglob("*.sqlite3")).parent.name
