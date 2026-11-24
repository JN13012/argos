"""Independent small app oracles; labels never passed to the mapping engine."""

import json

import pytest
from argos.backend.attack.recon.application_mapping import map_application

from test_application_mapping import assert_integrity, collect_responses
from test_web_runtime import setup as setup


@pytest.mark.parametrize("fixture", ["portal", "api", "spa"])
def test_measure_known_application_structures(setup, fixture):
    if fixture == "portal":
        root = b"""<a href="/help">h</a><a href="/help">again</a>
        <script src="/app.js"></script><form method="post" action="/session">
        <input name="email"><input name="password" type="password"></form>"""
        responses = [
            ("/", "text/html", root, (), 200),
            ("/help", "text/html", b"help", (), 200),
        ]
        expected = {"/", "/help", "/app.js", "/session"}
        operation_count, parameters, form_count = 3, {"email", "password"}, 1
        expected_relations = {
            ("navigation", "http://target/", "http://target/help"),
            ("resource", "http://target/", "http://target/app.js"),
        }
    elif fixture == "api":
        spec = dict(
            openapi="3.1.0",
            paths={
                "/api/items": dict(
                    get=dict(parameters=[{"name": "limit", "in": "query"}]),
                    post=dict(
                        requestBody=dict(
                            content={
                                "application/json": dict(
                                    schema=dict(
                                        properties={"title": dict(type="string")}
                                    )
                                )
                            }
                        )
                    ),
                ),
                "/api/items/{id}": dict(
                    delete=dict(parameters=[{"name": "id", "in": "path"}])
                ),
            },
        )
        responses = [
            ("/openapi.json", "application/json", json.dumps(spec).encode(), (), 200),
            ("/api/items?limit=5", "application/json", b"[]", (), 200),
        ]
        expected = {"/openapi.json", "/api/items", "/api/items/%7Bid%7D"}
        operation_count, parameters, form_count = 4, {"limit", "title", "id"}, 0
        expected_relations = {
            (
                "has_operation",
                "http://target/api/items",
                ("http://target/api/items", "GET"),
            ),
            (
                "has_operation",
                "http://target/api/items/%7Bid%7D",
                ("http://target/api/items/%7Bid%7D", "DELETE"),
            ),
        }
    else:
        responses = [
            (
                "/",
                "text/html",
                b'<div data-reactroot></div><script src="/app.js"></script>',
                (),
                200,
            ),
            (
                "/app.js",
                "application/javascript",
                b"/*! React v19.3.0 */ fetch('/api/users'); client.post('/api/order');",
                (),
                200,
            ),
        ]
        # A route that exists only after runtime state cannot be known statically.
        expected = {"/", "/app.js", "/api/users", "/api/order", "/runtime-only"}
        operation_count, parameters, form_count = 2, set(), 0
        expected_relations = {
            ("resource", "http://target/", "http://target/app.js"),
            ("javascript_reference", "http://target/app.js", "http://target/api/users"),
            ("javascript_reference", "http://target/app.js", "http://target/api/order"),
        }
    runtime, mid, _ = collect_responses(setup, responses)
    result = map_application(runtime.database, mid)
    assert_integrity(result)
    resources = {
        n["key"].removeprefix("http://target")
        for n in result["nodes"]
        if n["kind"] == "resource"
    }
    tp, fp, missed = (
        len(expected & resources),
        len(resources - expected),
        len(expected - resources),
    )
    assert fp == 0 and missed == (1 if fixture == "spa" else 0)
    assert (
        len([n for n in result["nodes"] if n["kind"] == "http_operation"])
        == operation_count
    )
    assert {
        n["key"][2] for n in result["nodes"] if n["kind"] == "parameter"
    } == parameters
    assert len([n for n in result["nodes"] if n["kind"] == "form"]) == form_count
    by_id = {n["id"]: n for n in result["nodes"]}

    def stable(key):
        return tuple(key) if isinstance(key, list) else key

    relations = {
        (
            e["relation"],
            stable(by_id[e["source"]]["key"]),
            stable(by_id[e["target"]]["key"]),
        )
        for e in result["relations"]
    }
    assert expected_relations <= relations
    unknown = sum(n["state"] == "unknown" for n in result["nodes"])
    assert unknown >= 1
    print(
        json.dumps(
            dict(
                fixture=fixture,
                resources_correct=tp,
                resources_false_positive=fp,
                resources_missed=missed,
                resource_precision=tp / (tp + fp),
                resource_recall=tp / len(expected),
                selected_relations_correct=len(expected_relations),
                selected_relations_expected=len(expected_relations),
                operation_nodes=operation_count,
                parameter_names=len(parameters),
                form_nodes=form_count,
                unknown_nodes=unknown,
                all_nodes_with_verified_sources=len(result["nodes"]),
                all_relations_with_verified_sources=len(result["relations"]),
                duplicates=result["metrics"]["duplicates"],
                dangling=result["metrics"]["dangling_relations"],
            )
        )
    )
