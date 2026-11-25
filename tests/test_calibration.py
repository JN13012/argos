"""Offline controls: proof binding, mission/directory separation, no extra GET."""

from uuid import uuid4

from argos.backend.attack.recon.calibration import controls
from argos.backend.attack.web.exploration import Exploration
from argos.backend.attack.web.transport import HTTPExchange

from test_web_runtime import setup as setup


def test_discovery_control_reuse_is_offline_and_bound_to_mission_and_directory(setup):
    runtime, mid, worker, _, _ = setup()
    worker.response = HTTPExchange(
        "completed", None, 200, (("Content-Type", "text/html"),), b"<p>shell</p>", True
    )
    with runtime:
        exploration = Exploration(runtime)
        run_id = exploration.start(mid)
        exploration.run(run_id)
    before = len(worker.calls)
    existing = controls(runtime.database, mid, "http://target/")
    assert len(existing) == 1
    assert existing == controls(runtime.database, mid, "http://target/", run_id=run_id)
    assert existing == controls(
        runtime.database, mid, "http://target/?lang=fr#fragment"
    )
    assert existing[0]["length"] == len(b"<p>shell</p>")
    assert existing[0]["evidence_sha256"]
    assert controls(runtime.database, mid, "http://target/app/") == []
    assert controls(runtime.database, mid, "http://other/") == []
    assert controls(runtime.database, uuid4(), "http://target/") == []
    assert len(worker.calls) == before
