"""Consume the existing browser archive without replaying the browser."""

from unittest.mock import patch
from uuid import UUID

import pytest
from argos.backend.attack.recon.application_mapping import (
    application_report,
    map_application,
)
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.receipts import WebIntegrityError, canonical, digest
from argos.backend.attack.web.store import WebStore

from test_application_mapping import assert_integrity, node
from test_web_browser_runtime import mission as mission


def test_archived_dom_links_are_inferred_without_browser_replay(mission):
    m = mission()
    result = m.navigation.navigate(m.run_id, m.route_id)
    assert result.state == "completed"
    calls = m.browser.calls
    with patch("socket.socket", side_effect=AssertionError("offline socket")):
        value = map_application(m.path, m.mission_id)
    assert_integrity(value)
    assert m.browser.calls == calls
    assert node(value, "resource", "http://target/dynamic")["state"] == "inferred"
    assert any(edge["relation"] == "dom_reference" for edge in value["relations"])
    assert "secret" not in canonical(value)
    assert len(value["navigation_ids"]) == 1
    assert application_report(m.path, UUID(value["id"])) == value
    with WebStore(m.path) as store, store.db:
        nav = NavigationStore(store).private(result.id)
        nav["execution"]["capture"]["links"] = ["http://target/altered"]
        nav["execution"]["capture_sha256"] = digest(nav["execution"]["capture"])
        store.db.execute(
            "UPDATE web_browser_navigations SET payload_json=?,payload_sha256=? "
            "WHERE id=?",
            (canonical(nav), digest(nav), str(result.id)),
        )
    with pytest.raises(WebIntegrityError):
        application_report(m.path, UUID(value["id"]))
