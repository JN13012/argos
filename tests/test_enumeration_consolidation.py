"""Real existing adapters share SPA calibration without a new request allowance."""

import os
from uuid import UUID

import pytest
from argos.backend.attack.recon.application_mapping import map_application
from argos.backend.attack.recon.calibration import controls
from argos.backend.attack.recon.context_execution import context_report, run_context
from argos.backend.attack.recon.context_plan import create_plan
from argos.backend.attack.recon.pipeline import run_pipeline
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.web.exploration import Exploration
from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.mission_store import MissionStore

from test_recon_network import application, missions, tools

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1", reason="Owned native SPA qualification"
)


@pytest.mark.parametrize("strategy", ["legacy", "contextual"])
def test_verified_control_is_shared_without_wildcard_abort(tmp_path, strategy):
    with application(wildcard=True) as (url, requested, _):
        db, verifier, mid, nid = missions(
            tmp_path,
            url,
            limits=dict(max_requests=150, duration_seconds=900, requests_per_second=10),
        )
        try:
            if strategy == "legacy":
                value = run_pipeline(
                    db,
                    verifier,
                    mid,
                    directories=("unlinked", "ghost"),
                    files=("openapi.json",),
                    tools=tools(),
                )
                stages = [
                    s for s in value["stages"] if s["tool"] in {"gobuster", "ffuf"}
                ]
            else:
                with WebRuntime(db, verifier, worker=HTTPWorker(tools())) as runtime:
                    exploration = Exploration(runtime)
                    exploration.run(exploration.start(mid))
                assert controls(db, mid, url + "subdir/") == []
                mapping = map_application(db, mid)
                d, f = tmp_path / "d.txt", tmp_path / "f.txt"
                d.write_text("unlinked\nghost\n")
                f.write_text("openapi.json\n")
                plan = create_plan(
                    db,
                    UUID(mapping["id"]),
                    directories=str(d),
                    files=str(f),
                    max_candidates=3,
                    request_budget=16,
                    strategy="predefined",
                )
                value = run_context(db, verifier, UUID(plan["id"]), tools=tools())
                stages = value["stages"]
                assert value["coverage"]["duplicate_candidate_requests"] == 0
                assert value["coverage"]["outcomes"]["generic_response_suspected"] == 1
                assert context_report(db, UUID(value["id"])) == value
                with ReconStore(db) as archive:
                    forged = archive.get(UUID(value["id"]))
                    forged["stages"][0]["calibration"][0]["length"] += 1
                    archive.save(forged)
                with pytest.raises(WebIntegrityError):
                    context_report(db, UUID(value["id"]))
                with ReconStore(db) as archive:
                    archive.save(value)
            assert "/unlinked" in requested and "/ghost" in requested
            for stage in stages:
                assert stage["calibration"]
                assert stage["profile"]["exclude_lengths"]
                assert stage.get("reason") != "wildcard_precheck"
                assert stage["entries_without_response"] == 0
            print(
                strategy,
                [
                    (s["tool"], s["state"], s.get("reason"), s["entries_with_response"])
                    for s in stages
                ],
            )
        finally:
            with MissionStore(db) as store:
                store.revoke(mid)
                store.revoke(nid)
