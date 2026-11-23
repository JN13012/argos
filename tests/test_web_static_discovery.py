"""Static references join the existing signed HTTP frontier, never execute code."""

import json
from uuid import UUID

import pytest
from argos.backend.api.routes.results import details
from argos.backend.attack.web.discovery import inspect_response
from argos.backend.attack.web.exploration import Exploration
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.receipts import canonical, digest
from argos.backend.attack.web.static_discovery import STATIC_BYTES
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPExchange
from argos.backend.core.config import ResultSource

from test_web_discovery import html, result, site
from test_web_runtime import setup as setup


def resource(body, mime="application/javascript"):
    return HTTPExchange(
        "completed", None, 200, (("Content-Type", mime),), body.encode(), True
    )


def test_root_spa_shell_is_not_soft404_and_its_scripts_are_explored(setup):
    runtime, mid, worker, resolver, _ = setup()
    shell = html('<script src="/main.js"></script><a href="/unknown">x</a>')
    site(
        worker,
        {
            "_missing": shell,
            "/": shell,
            "/unknown": shell,
            "/main.js": resource('fetch("/api/public");'),
            "/api/public": resource('{"ok":true}', "application/json"),
        },
    )
    with runtime:
        run_id, report = result(runtime, mid)
        with WebStore(runtime.database) as store:
            routes = {r["url"]: r for r in Frontier(store.db).routes(run_id)}
            assert routes["http://target/"]["reason"] == "spa_shell"
            assert routes["http://target/"]["state"] == "visited"
            assert routes["http://target/unknown"]["reason"] == "suspected_soft_404"
            endpoint = routes["http://target/api/public"]
            assert endpoint["reason"] == "non_html"
            assert endpoint["provenance"][0]["kind"] == "javascript"
            source = UUID(endpoint["provenance"][0]["source_request_id"])
            capture = Frontier(store.db).capture(source)
            assert (
                capture is not None
                and capture["references"][0]["url"] == endpoint["url"]
            )
            proof = store.evidence(source)
            assert proof and proof["discovery_sha256"] == digest(capture)
            assert report["confirmed_findings"] == 0
            projection = details(
                store, ResultSource(label="test", database=runtime.database), mid
            )
            root = next(
                r for r in projection["requests"] if r["url"] == "http://target/"
            )
            assert root["classification"] == "response_observed"
            api = next(
                r for r in projection["requests"] if r["url"].endswith("/api/public")
            )
            assert (
                api["provenance"][0]["kind"] == "javascript"
                and api["verification"] == "verified"
            )
        assert set(resolver.calls) == {"target"}


def test_modules_openapi_and_static_only_candidates_with_provenance(setup):
    runtime, mid, worker, _, _ = setup()
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/catalog": {"get": {}},
            "/api/items/{id}": {"get": {}},
            "/api/write": {"post": {}},
        },
    }
    site(
        worker,
        {
            "/": html(
                '<script type="module" src="/assets/main.js"></script>'
                '<a href="/api/catalog">x</a><a href="/spec">schema</a>'
            ),
            "/assets/main.js": resource(
                'import "./chunk.js"; client.get("/api/catalog"); '
                'const r={path:"settings/:id"}; client.post("/api/write",{});'
            ),
            "/assets/chunk.js": resource('fetch("/api/version");'),
            "/spec": resource(json.dumps(spec), "application/json"),
            "/api/catalog": resource("[]", "application/json"),
            "/api/version": resource('{"version":"test"}', "application/json"),
        },
    )
    with runtime:
        run_id, _ = result(runtime, mid)
        with WebStore(runtime.database) as store:
            routes = {r["url"]: r for r in Frontier(store.db).routes(run_id)}
            catalog = routes["http://target/api/catalog"]
            assert {p["kind"] for p in catalog["provenance"]} == {
                "html",
                "javascript",
                "openapi",
            }
            assert routes["http://target/api/version"]["request_id"]
            for path in ("/api/items/%7Bid%7D", "/api/write", "/settings/:id"):
                route = routes["http://target" + path]
                assert (
                    route["reason"] == "static_reference"
                    and route["request_id"] is None
                )
            assert (
                len(
                    [
                        c
                        for c in worker.calls
                        if c[0].preflight.request.url.endswith("/api/catalog")
                    ]
                )
                == 1
            )


def test_static_discovery_obeys_scope_effects_and_signed_request_budget(setup):
    runtime, mid, worker, resolver, _ = setup(
        limits=dict(max_requests=4, requests_per_second=100)
    )
    site(
        worker,
        {
            "/": html('<script src="/app.js"></script>'),
            "/app.js": resource(
                'fetch("http://outside/secret"); fetch("/logout"); '
                'fetch("/api/one"); fetch("/api/two");'
            ),
            "/api/one": resource("{}", "application/json"),
        },
    )
    with runtime:
        run_id, report = result(runtime, mid)
        assert len(worker.calls) == 4
        assert set(resolver.calls) == {"target"}
        assert report["reason"] == "budget_exhausted"
        with WebStore(runtime.database) as store:
            routes = Frontier(store.db).routes(run_id)
            assert (
                next(r for r in routes if r["url"] == "http://outside/secret")["state"]
                == "excluded"
            )
            assert (
                next(r for r in routes if r["url"].endswith("/logout"))["reason"]
                == "effect_denied"
            )


def test_static_candidate_can_be_verified_by_a_later_wordlist_without_duplication(
    setup,
):
    runtime, mid, worker, _, _ = setup()
    site(
        worker,
        {
            "/": html('<script src="/app.js"></script>'),
            "/app.js": resource('const r={path:"catalog"}'),
            "/catalog": html("catalog"),
        },
    )
    with runtime:
        engine = Exploration(runtime)
        run_id = engine.start(mid)
        engine.run(run_id, finalize=False)
        with WebStore(runtime.database) as store:
            frontier = Frontier(store.db)
            config = runtime.policy.configuration(mid)
            frontier.enqueue_candidates(
                run_id, config, runtime.owner, ["http://target/catalog"]
            )
        engine.run(run_id)
        with WebStore(runtime.database) as store:
            candidates = [
                r
                for r in Frontier(store.db).routes(run_id)
                if r["url"].endswith("/catalog")
            ]
            assert len(candidates) == 1 and candidates[0]["state"] == "visited"
            assert {p["kind"] for p in candidates[0]["provenance"]} == {
                "javascript",
                "wordlist",
            }


@pytest.mark.parametrize(
    "source,expected",
    [
        ('fetch("/read"); // fetch("/comment")\n/* "/other" */', [("/read", True)]),
        (
            'http.post("/write",{}); fetch("/other",{method:"POST"});',
            [("/write", False), ("/other", False)],
        ),
        ('http.get("/items/"+id); const x=`/api/${id}`;', [("/items/", False)]),
        ('const x="\\x2fapi\\u002finfo";', [("/api/info", False)]),
        (
            'import "./chunk.js"; import("./next.js");',
            [("/chunk.js", True), ("/next.js", True)],
        ),
        ('const value="http://[";', []),
    ],
)
def test_literal_extraction_is_bounded_and_does_not_evaluate(source, expected):
    capture = inspect_response("http://target/app.js", resource(source))
    assert sorted(
        [
            (r["url"].removeprefix("http://target"), r["verify"])
            for r in capture["references"]
        ]
    ) == sorted(expected)


def test_bounded_property_reads_and_dynamic_templates_are_distinct():
    capture = inspect_response(
        "http://target/app.js",
        resource(
            'class Catalog{host=env.url+"/api/catalog";'
            'find(){return this.http.get(this.host+"/")}}'
            'class Other{host=env.url+"/api/unknown";} '
            "class Writer{post(){return this.http.post(this.host,{})}}"
            "fetch(`${env.host}/api/search?q=${term}`);"
        ),
    )
    references = {r["url"]: r for r in capture["references"]}
    assert references["http://target/api/catalog"]["verify"]
    assert (
        references["http://target/api/catalog"]["relation"] == "constant_read_reference"
    )
    assert not references["http://target/api/unknown"]["verify"]
    assert not references["http://target/api/search"]["verify"]
    assert references["http://target/api/search"]["relation"] == "template_prefix"


def test_parser_mime_and_size_limits():
    assert (
        inspect_response(
            "http://target/app.js", resource('fetch("/api")', "text/plain")
        )["links"]
        == []
    )
    capture = inspect_response(
        "http://target/app.js", resource('fetch("/api");' + " " * (STATIC_BYTES + 1))
    )
    assert capture["reason"] == "static_limit" and capture["links"] == []
    capture = inspect_response(
        "http://target/app.js",
        resource(";".join(f'fetch("/api/{i}")' for i in range(400))),
    )
    assert capture["public"]["parser_limited"]
    assert len(capture["links"]) <= 256 and len(canonical(capture).encode()) <= 65536
    assert len(capture["links"]) == len(capture["references"])


@pytest.mark.parametrize(
    "spec",
    [
        {"openapi": "3.0.0", "servers": [{"url": 42}], "paths": {}},
        {"swagger": "2.0", "basePath": [], "paths": {}},
        {"openapi": "3.0.0", "servers": [{"url": "https://{host}"}], "paths": {}},
        {"paths": {"/invented": {"get": {}}}},
    ],
)
def test_malformed_or_non_openapi_json_never_expands(spec):
    capture = inspect_response(
        "http://target/openapi.json", resource(json.dumps(spec), "application/json")
    )
    assert capture["links"] == []


def test_provenance_bytes_are_charged_before_the_first_http_request(setup):
    runtime, mid, worker, _, _ = setup(execution=dict(evidence_bytes=2097152))
    with runtime:
        run_id, report = result(runtime, mid)
        assert report["reason"] == "budget_exhausted"
        assert not worker.calls
        with WebStore(runtime.database) as store:
            assert Frontier(store.db).provenance_quota(mid) > 0
            assert len(Frontier(store.db).routes(run_id)) == 2
