import hashlib
import json

import pytest
from benchmarks.recon_v2 import fixtures
from benchmarks.recon_v2.audit import CATALOG, raw_replay, read_json, verify_archive


@pytest.mark.parametrize("name", ["portal", "spa", "api"])
def test_controlled_application_matches_independent_reference(name):
    app = getattr(fixtures, name)
    responses = {}
    for expected in read_json(CATALOG)["fixtures"][name]:
        path = expected["path"]
        result = {}

        def start(status, headers, result=result):
            result.update(status=int(status.split()[0]), headers=dict(headers))

        body = b"".join(
            app({"REQUEST_METHOD": expected["method"], "PATH_INFO": path}, start)
        )
        assert result["status"] == expected["status"]
        assert ("WWW-Authenticate" in result["headers"]) == (
            expected["authentication"] == "required"
        )
        responses[path] = body

    if name == "spa":
        assert responses["/absent"] == responses["/"]
        assert b"/cards/blue" not in responses["/"]
        assert json.loads(responses["/api/cards"])[0]["url"] == "/cards/blue"
    if name == "api":
        assert "get" in json.loads(responses["/openapi.json"])["paths"]["/v1/books"]


def test_archive_pin_and_entry_validation(tmp_path):
    item = tmp_path / "trial.json"
    item.write_bytes(b"{}")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({item.name: hashlib.sha256(b"{}").hexdigest()}))
    pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert item.name in verify_archive(tmp_path, pin)
    item.write_bytes(b"[]")
    with pytest.raises(ValueError, match="Archive entry differs"):
        verify_archive(tmp_path, pin)
    with pytest.raises(ValueError, match="Manifest differs"):
        verify_archive(tmp_path, "0" * 64)


def test_raw_replay_distinguishes_token_loss_from_absence():
    body = b'fetch("/visible"); "' + b"x" * 8200 + b'/lost";'
    replay = raw_replay(
        body, "http://fixture.invalid/main.js", {"/visible", "/lost", "/absent"}
    )
    assert replay["/visible"]["normalized"] == ["http_reference"]
    assert replay["/lost"]["literal_hits"] == 1
    assert replay["/lost"]["oversized_tokens"] == [8205]
    assert replay["/lost"]["normalized"] == []
    assert replay["/absent"]["literal_hits"] == 0
