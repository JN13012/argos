"""Loopback relay gates: unplanned paths, duplicates and request ceilings."""

import http.client
import os

import pytest
from argos.backend.attack.recon.relay import EnumerationRelay

from test_web_runtime import setup as setup

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1", reason="Owned private relay sockets"
)


@pytest.mark.parametrize("tool", ["gobuster", "ffuf"])
def test_context_relay_refuses_unplanned_and_duplicate_paths(setup, tool):
    runtime, mid, worker, _, _ = setup()
    admitted = set()
    count = 0

    def admit(target, candidate):
        nonlocal count
        if candidate and target in admitted:
            return "duplicate_target_not_replayed"
        if count >= 1:
            return "request_budget"
        count += 1
        if candidate:
            admitted.add(target)
        return None

    with (
        runtime,
        EnumerationRelay(
            runtime,
            mid,
            "http://target/",
            active=lambda: True,
            maximum=8,
            entries=("planned",),
            tool=tool,
            strict_entries=True,
            admit=admit,
        ) as relay,
    ):

        def call(path):
            connection = http.client.HTTPConnection(
                "127.0.0.1", relay.server.server_port, timeout=5
            )
            try:
                connection.request("GET", "/" + relay.token + "/" + path)
                response = connection.getresponse()
                response.read()
                return response.status
            finally:
                connection.close()

        assert call("outside-plan") == 403
        assert call("../escape") == 400
        assert not worker.calls
        assert call("planned") == 200
        assert call("planned") == 403
        assert call("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb") == (
            429 if tool == "gobuster" else 403
        )
        assert len(worker.calls) == 1
        assert "duplicate_target_not_replayed" in relay.errors
