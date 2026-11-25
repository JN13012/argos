import json
from subprocess import Popen

from argos.backend.attack.review.capabilities import capability_registry
from argos.backend.core.tool_registry import ToolRegistry
from argos.cli import main

from test_tool_registry import registry_file


def by_id(report, name):
    return next(item for item in report["capabilities"] if item["id"] == name)


def test_inventory_is_deterministic_and_does_not_probe_by_default(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("Inventory must not probe tools automatically")

    monkeypatch.setattr(ToolRegistry, "load", forbidden)
    monkeypatch.setattr(Popen, "__init__", forbidden)
    assert main(["review", "capabilities"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == json.loads(json.dumps(capability_registry()))
    assert [item["id"] for item in result["capabilities"]] == sorted(
        {item["id"] for item in result["capabilities"]}
    )
    passive = by_id(result, "fingerprinting")
    assert passive["availability"]["environment"] == "local_reader"
    network = by_id(result, "network_inventory")
    assert network["availability"]["tool_dependencies"] == {"nmap": "not_checked"}
    assert network["availability"]["mission"] == "not_checked"


def test_inventory_reuses_registry_identity_without_executing(
    tmp_path, monkeypatch, capsys
):
    config = registry_file(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("Inventory must not execute tools")

    monkeypatch.setattr(Popen, "__init__", forbidden)
    args = ["review", "capabilities", "--registry", str(config)]
    assert main(args) == 0
    output = capsys.readouterr().out
    assert str(tmp_path) not in output
    result = json.loads(output)
    network = by_id(result, "network_inventory")
    assert network["availability"]["tool_dependencies"] == {"nmap": "identity_verified"}
    context = by_id(result, "contextual_enumeration")
    assert context["availability"]["tool_dependencies"] == {
        "ffuf": "missing",
        "gobuster": "missing",
    }
    with (tmp_path / "binary").open("ab") as stream:
        stream.write(b"changed")
    assert main(args) == 0
    network = by_id(json.loads(capsys.readouterr().out), "network_inventory")
    assert network["availability"]["tool_dependencies"] == {"nmap": "invalid"}
