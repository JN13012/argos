"""Redirect IPC remains closed and cannot activate the old relay mode."""

import pytest
from argos.backend.attack.web.browser import BrowserHopRequest

from test_web_browser import relay as relay
from test_web_browser import request


def test_old_relay_refuses_new_metadata(relay):
    assert relay.answer(dict(request(), resource_id=1, redirected_from=None)) == {
        "blocked": True
    }
    relay.mediator.assert_not_called()


def test_redirect_relay_passes_only_typed_metadata(relay):
    relay.redirects = {"max_hops": 5}
    assert (
        relay.answer(dict(request(), resource_id=1, redirected_from=None))["status"]
        == 200
    )
    value = relay.mediator.call_args.args[0]
    assert isinstance(value, BrowserHopRequest) and value.resource_id == 1
    assert "secret" not in repr(value)


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"resource_id": True, "redirected_from": None},
        {"resource_id": 65, "redirected_from": None},
        {"resource_id": 2, "redirected_from": 2},
        {"resource_id": 2, "redirected_from": False},
        {"resource_id": 2, "redirected_from": 0},
        {"resource_id": 1, "redirected_from": None, "headers": {"Cookie": "private"}},
    ],
)
def test_redirect_protocol_refuses_missing_forged_or_extra_fields(relay, fields):
    relay.redirects = {"max_hops": 5}
    assert relay.answer(dict(request(), **fields)) == {"blocked": True}
    relay.mediator.assert_not_called()
