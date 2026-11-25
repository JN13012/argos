"""Independent positive and negative controls for generic signals v2."""

from argos.backend.attack.recon.fingerprint_signals import (
    EXTRACTION_RULESET,
    MAX_JAVASCRIPT,
    http_indicators,
    http_indicators_v2,
)

from test_web_runtime import setup as setup


def signals(body, mime="application/javascript", *, complete=True, headers=()):
    return http_indicators_v2(
        [("Content-Type", mime), *headers], body, complete=complete
    )


def test_complete_minified_libraries_beyond_legacy_body_limit():
    # Evaluator labels are not imported by the engine; arbitrary vendor padding
    # exercises complete retained bundles rather than a lab-specific filename.
    angular = (
        b"x;" * 170000 + b"Widget.\\u0275fac=function(){};Widget.\\u0275cmp={};"
        b'["ng-version","18.2.9"];'
    )
    react = (
        b"x;" * 170000
        + b"Symbol.for('react.element');Symbol.for('react.portal');"
        + b"x.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED={};x.version='99.9.9';"
    )
    for body, tech, version in [(angular, "angular", "18.2.9"), (react, "react", None)]:
        value = signals(body)
        assert value["ruleset"] == EXTRACTION_RULESET and not value["limited"]
        assert [(s["technology"], s["version"]) for s in value["signals"]] == [
            (tech, version)
        ]
        assert not http_indicators(
            [("Content-Type", "application/javascript")], body, complete=True
        )["signals"]
        assert not signals(body, complete=False)["signals"]


def test_decoys_mime_truncation_and_analysis_ceiling():
    for body in [
        b'Symbol.for("react.element");',
        b'"React Angular __ngContext__ Zone.js";',
        b"Widget.\\u0275cmp={};",
        b'exports.version="18.0.0";',
    ]:
        assert not signals(body)["signals"]
    implementation = b"Widget.\\u0275fac=function(){};Widget.\\u0275cmp={};"
    assert not signals(implementation, "text/plain")["signals"]
    huge = implementation + b"x" * MAX_JAVASCRIPT
    result = signals(huge)
    assert result["limited"] and not result["signals"]
    assert not signals(b"<app-root></app-root>", "text/html")["signals"]


def test_declared_cdn_is_explicit_and_not_arbitrary_filename_or_foreign_host():
    body = b'<script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>'
    value = signals(body, "text/html")
    assert value["signals"][0]["rule"] == "declared-cdn-jquery"
    assert value["signals"][0]["version"] == "3.6.4"
    for src in [
        "jquery-3.6.4.js",
        "https://code.jquery.com.attacker.invalid/jquery-3.6.4.min.js",
        "https://code.jquery.com:7777/jquery-3.6.4.min.js",
    ]:
        assert not signals(f'<script src="{src}"></script>'.encode(), "text/html")[
            "signals"
        ]


def test_openresty_does_not_assign_its_release_number_to_nginx():
    result = signals(b"", headers=[("Server", "openresty/1.25.3.2")])
    found = {s["technology"]: s for s in result["signals"]}
    assert found["openresty"]["version"] == "1.25.3.2"
    assert found["nginx"]["version"] is None
    assert found["nginx"]["source"] == "http"


def test_versioned_probed_openresty_preserves_old_nmap_projections():
    from argos.backend.attack.pentest.models import PortObservation
    from argos.backend.attack.recon.fingerprint_signals import (
        CORRELATION_RULESET,
        nmap_indicators,
    )

    port = PortObservation(
        "127.0.0.1",
        8080,
        "tcp",
        "open",
        "http",
        version="1.25.3.2",
        product="OpenResty web app server",
        service_method="probed",
        service_confidence=10,
    )
    assert nmap_indicators(port) == []
    actual = nmap_indicators(port, ruleset=CORRELATION_RULESET)
    assert [(i.technology, i.version) for i in actual] == [("openresty", "1.25.3.2")]


def test_new_capture_provenance_and_version_conflicts_remain_verifiable(setup):
    from uuid import UUID

    from argos.backend.attack.recon.fingerprint import fingerprint, fingerprint_report
    from argos.backend.attack.web.contracts import WebRequest
    from argos.backend.attack.web.transport import HTTPExchange

    runtime, mid, worker, _, _ = setup()
    with runtime:
        for index, version in enumerate(("17.3.1", "18.2.9")):
            body = (
                f'C.ɵfac=function(){{}};C.ɵcmp={{}};["ng-version","{version}"];'
            ).encode()
            worker.response = HTTPExchange(
                "completed",
                None,
                200,
                (("Content-Type", "application/javascript"),),
                body,
                True,
            )
            rid = runtime.submit(WebRequest(mid, f"http://target/bundle-{index}.js"))
            assert runtime.run(rid).state == "completed"
    value = fingerprint(runtime.database, mid)
    found = next(i for i in value["identifications"] if i["technology"] == "angular")
    assert found["status"] == "contradictory" and found["version"] is None
    assert found["versions"] == ["17.3.1", "18.2.9"]
    assert len(found["evidence"]) == 2
    assert fingerprint_report(runtime.database, UUID(value["id"])) == value
