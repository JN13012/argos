"""Input fixtures only; expectations are evaluator data, never engine inputs."""

import json

import pytest
from argos.backend.attack.recon.mapping_signals import (
    MAX_BYTES,
    MAX_FACTS,
    application_signals,
    location,
)


def signals(body, media="text/html", **kwargs):
    return application_signals(
        "http://target/root", (("Content-Type", media),), body, **kwargs
    )


def test_html_form_controls_and_authentication_are_minimized():
    body = b"""<base href="/app/"><a href="/help?q=private-query">Help</a>
    <form action="/session?next=private-next" method="post">
    <input name="email" type="email" value="private-email">
    <input name="password" type="password" value="private-password">
    <input name="csrf" type="hidden" value="private-token"></form>
    <script src="/app.js"></script>"""
    result = signals(body)
    assert not result["limited"]
    facts = result["facts"]
    form = next(f for f in facts if f["kind"] == "form")
    assert form["method"] == "POST" and form["target"]["url"] == "http://target/session"
    assert form["target"]["query"] == ["next"]
    assert {f["name"] for f in facts if f["kind"] == "field"} == {
        "email",
        "password",
        "csrf",
    }
    assert any(f.get("mechanism") == "password_form" for f in facts)
    assert "private-" not in json.dumps(result)


def test_json_api_operations_parameters_security_no_reference_resolution():
    spec = dict(
        openapi="3.1.0",
        servers=[dict(url="/v1")],
        security=[dict(token=[])],
        paths={
            "/items/{id}": {
                "parameters": [dict(name="id", **{"in": "path"})],
                "get": dict(parameters=[dict(name="filter", **{"in": "query"})]),
                "patch": dict(
                    requestBody=dict(
                        content={
                            "application/json": dict(
                                schema=dict(
                                    properties={
                                        "title": dict(
                                            type="string", example="private-value"
                                        )
                                    }
                                )
                            )
                        }
                    )
                ),
            },
            "/anonymous": dict(get=dict(security=[])),
            "/external": {"$ref": "https://elsewhere.invalid/spec.json"},
        },
    )
    result = signals(json.dumps(spec).encode(), "application/json")
    assert result["limited"]
    operations = [f for f in result["facts"] if f["kind"] == "operation"]
    assert {f["method"] for f in operations} == {"GET", "PATCH"}
    assert len(operations) == 3
    assert {f["name"] for f in result["facts"] if f["kind"] == "parameter"} == {
        "id",
        "filter",
        "title",
    }
    assert "private-value" not in json.dumps(result)
    assert "elsewhere" not in json.dumps(result)


def test_static_javascript_references_do_not_attest_method_support():
    result = signals(
        b"fetch('/api/users'); client.post('/api/login'); const msg='ordinary text';",
        "application/javascript",
    )
    assert {f["kind"] for f in result["facts"]} == {"response", "reference"}
    assert {
        f["target"]["url"] for f in result["facts"] if f["kind"] == "reference"
    } == {"http://target/api/users", "http://target/api/login"}


@pytest.mark.parametrize(
    "body",
    [
        b'{"openapi":"3.0.0","openapi":"3.1.0","paths":{}}',
        b'{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":true}}}}',
        b'{"openapi":"3.0.0","servers":[{}],"paths":{}}',
    ],
)
def test_malformed_documents_are_bounded_and_flagged(body):
    assert signals(body, "application/json")["limited"]


def test_caps_incomplete_credential_urls_and_challenge_redaction():
    result = signals((b'<a href="/p">x</a>' * 500), complete=False)
    assert result["limited"] and not any(
        f["kind"] == "reference" for f in result["facts"]
    )
    result = signals(b"".join(f'<a href="/p{i}">x</a>'.encode() for i in range(300)))
    assert result["limited"] and len(result["facts"]) <= MAX_FACTS
    assert len(json.dumps(result).encode()) <= MAX_BYTES + 4096
    assert location("http://target/", "https://user:password@outside.invalid/x") is None
    result = application_signals(
        "http://target/", (("WWW-Authenticate", 'Basic realm="private-realm"'),), b""
    )
    assert any(f.get("mechanism") == "basic" for f in result["facts"])
    assert "private-realm" not in json.dumps(result)
