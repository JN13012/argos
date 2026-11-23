"""Read-only API projection; no target or worker networking."""

import hashlib
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from argos.backend.api.main import create_app
from argos.backend.api.routes.results import classification, database
from argos.backend.attack.pentest.evidence_store import EvidenceStore, ScanEvidence
from argos.backend.attack.pentest.models import PortObservation, ScanObservation
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.transport import HTTPExchange
from argos.backend.core.config import ResultReport, ResultSource, Settings
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from test_web_runtime import setup as setup


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def dataset(setup, tmp_path):
    runtime, mid, worker, _, _ = setup()
    worker.response = HTTPExchange(
        "completed", None, 500, (("Set-Cookie", "SECRET_COOKIE"),), b"SECRET_BODY", True
    )
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/api?token=SECRET_QUERY"))
        snapshot = runtime.run(rid)
    jid = uuid4()
    now = datetime.now(UTC)
    with EvidenceStore(runtime.database) as store:
        scan_receipt = store.save(
            ScanEvidence(
                jid,
                mid,
                "127.0.0.1",
                "recon",
                "completed",
                ("/usr/bin/nmap", "127.0.0.1"),
                now,
                now,
                0,
                (
                    b'<nmaprun><host><address addr="127.0.0.1" '
                    b'addrtype="ipv4"/></host></nmaprun>'
                ),
                b"SECRET_STDERR",
                ScanObservation(
                    "127.0.0.1",
                    (PortObservation("127.0.0.1", 3000, "tcp", "open", "http", None),),
                ),
            )
        )
    with ReconStore(runtime.database) as store:
        store.initialize()
        store.save(
            dict(
                id=str(uuid4()),
                mission_id=str(mid),
                created_at=now.isoformat(),
                status="partial",
                stages=[
                    dict(
                        tool="nmap",
                        job_id=str(jid),
                        state="completed",
                        evidence_sha256=scan_receipt.record_sha256,
                    ),
                    dict(
                        tool="ffuf",
                        state="completed",
                        exit_code=0,
                        requests=[
                            dict(
                                request_id=str(rid),
                                evidence_sha256=snapshot.evidence_sha256,
                            )
                        ],
                    ),
                ],
            )
        )
    report = tmp_path / "report.html"
    report.write_text("<html>Approved existing report</html>")
    source = ResultSource(
        label="Owned source",
        database=runtime.database,
        wordlist_provenance="targeted",
        reports={
            "html": ResultReport(label="HTML report", path=report),
        },
    )
    settings = IsolatedSettings(result_sources={"lab": source})
    return create_app(settings), runtime.database, mid, rid, source, report


@pytest.mark.anyio
async def test_real_store_projection_is_readonly_and_redacted(dataset):
    app, path, mid, _, source, _ = dataset
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        catalog = await c.get("/api/v1/results")
        assert catalog.status_code == 200
        assert catalog.json()["sources"][0]["missions"][0]["id"] == str(mid)
        response = await c.get(f"/api/v1/results/lab/missions/{mid}")
        assert response.status_code == 200
        data = response.json()
        assert data["ports"][0]["port"] == 3000
        assert data["tools"][0]["exit_code"] == 0
        assert data["requests"][0]["classification"] == "http_error"
        assert data["requests"][0]["wordlist_provenance"] == "targeted"
        assert data["requests"][0]["verification"] == "verified"
        assert data["evidence"][0]["verification"] == "verified"
        for secret in ("SECRET", str(path), "/usr/bin", "stdout_xml", "signature"):
            assert secret not in response.text
        assert data["requests"][0]["url"] == "http://target/api"
        assert data["technologies"] == []
        assert response.headers["cache-control"] == "no-store"
        assert (await c.post("/api/v1/results")).status_code == 405
        assert (await c.get(f"/api/v1/results/other/missions/{mid}")).status_code == 404
        assert (
            await c.get(f"/api/v1/results/lab/missions/{uuid4()}")
        ).status_code == 404
    with database(source) as web:
        with pytest.raises(sqlite3.OperationalError):
            web.db.execute("DELETE FROM pentest_missions")
    assert before == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.anyio
async def test_corrupt_receipt_fails_closed(dataset):
    app, path, mid, rid, _, _ = dataset
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE web_http_evidence SET payload_json='{}' WHERE request_id=?",
            (str(rid),),
        )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        response = await c.get(f"/api/v1/results/lab/missions/{mid}")
    assert response.status_code == 409
    assert "Stored evidence verification failed" in response.text
    assert str(path) not in response.text


@pytest.mark.anyio
async def test_only_exact_configured_reports_are_downloadable(dataset, tmp_path):
    app, _, _, _, _, report = dataset
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        response = await c.get("/api/v1/results/lab/reports/html")
        assert response.status_code == 200
        assert response.content == report.read_bytes()
        assert "attachment" in response.headers["content-disposition"]
        assert "sandbox" in response.headers["content-security-policy"]
        assert (
            await c.get("/api/v1/results/lab/reports/not-approved")
        ).status_code == 404
        report.unlink()
        private = tmp_path / "secret"
        private.write_text("PRIVATE_FILE")
        report.symlink_to(private)
        response = await c.get("/api/v1/results/lab/reports/html")
        assert response.status_code == 404 and "PRIVATE_FILE" not in response.text


@pytest.mark.anyio
async def test_default_disabled_and_unavailable_source(tmp_path):
    source = ResultSource(label="Unavailable", database=tmp_path / "missing.sqlite")
    for sources, count in (({}, 0), ({"missing": source}, 1)):
        app = create_app(IsolatedSettings(result_sources=sources))
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            response = await c.get("/api/v1/results")
        assert len(response.json()["sources"]) == count
        assert str(tmp_path) not in response.text
    assert not (tmp_path / "missing.sqlite").exists()


@pytest.mark.parametrize(
    "source",
    [
        {"label": "Bad", "database": "relative.sqlite"},
        {
            "label": "Bad",
            "database": "/absolute.sqlite",
            "reports": {"../secret": {"label": "Bad", "path": "/secret"}},
        },
    ],
)
def test_source_config_rejects_ambiguous_paths(source):
    with pytest.raises(ValidationError):
        ResultSource.model_validate(source)


@pytest.mark.parametrize(
    ("route", "response", "probe", "expected"),
    [
        (
            {"reason": "suspected_soft_404", "state": "blocked"},
            {"status": 200},
            False,
            "spa_generic",
        ),
        (
            {"reason": "html", "state": "visited"},
            {"status": 200},
            False,
            "route_observed",
        ),
        (
            {"reason": "non_html", "state": "blocked"},
            {"status": 200},
            False,
            "response_observed",
        ),
        (None, {"status": 500}, False, "http_error"),
        (None, {"status": 200}, True, "probe"),
        (None, None, False, "unverified"),
    ],
)
def test_no_generic_or_error_response_claimed_as_confirmed_route(
    route, response, probe, expected
):
    assert classification(route, response, probe=probe) == expected


@pytest.mark.anyio
@pytest.mark.parametrize("store", ["nmap", "recon"])
async def test_corrupt_tool_metadata_is_not_shown_as_verified(dataset, store):
    app, path, mid, _, _, _ = dataset
    with sqlite3.connect(path) as db:
        if store == "nmap":
            db.execute("UPDATE pentest_scan_evidence SET record_sha256=?", ("0" * 64,))
        else:
            db.execute("UPDATE recon_runs SET sha256=?", ("0" * 64,))
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        response = await c.get(f"/api/v1/results/lab/missions/{mid}")
    assert response.status_code == 409
    assert str(path) not in response.text


@pytest.mark.anyio
async def test_large_report_and_symlink_database_are_rejected(dataset, tmp_path):
    app, path, mid, _, _, report = dataset
    with report.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/api/v1/results/lab/reports/html")).status_code == 404
        moved = tmp_path / "moved.sqlite"
        path.rename(moved)
        path.symlink_to(moved)
        response = await c.get(f"/api/v1/results/lab/missions/{mid}")
        assert response.status_code == 503
        assert str(moved) not in response.text
