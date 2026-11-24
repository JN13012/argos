"""Bounded network plans and durable inventory; no target traffic in unit tests."""

from threading import Event
from unittest.mock import patch

import pytest
from argos.backend.attack.pentest.planner import network_plans
from argos.backend.attack.recon.network import network_report, run_network
from argos.cli import main

from test_network_worker import approved


@pytest.mark.parametrize(
    "profile,hosts,ports,jobs",
    [
        ("quick", 1, 32, 1),
        ("standard", 4, 128, 16),
        ("deep", 8, 256, 64),
    ],
)
def test_network_profiles_bound_jobs(profile, hosts, ports, jobs):
    targets = tuple(f"10.0.0.{n + 1}" for n in range(hosts))
    plans = network_plans(profile, targets, tuple(range(1, ports + 1)))
    assert len(plans) == jobs
    assert all(len(plan.ports) <= 32 for _, plan in plans)
    with pytest.raises(ValueError):
        network_plans(profile, targets, tuple(range(1, ports + 2)))
    with pytest.raises(ValueError):
        network_plans(profile, targets + ("10.0.1.1",), (80,))


@pytest.mark.parametrize(
    "targets,ports",
    [
        (("127.0.0.1/24",), (80,)),
        (("localhost",), (80,)),
        (("127.0.0.1", "127.0.0.1"), (80,)),
        (("127.0.0.1",), (0,)),
        (("127.0.0.1",), (80, 80)),
        (("127.0.0.1",), (81, 80)),
    ],
)
def test_network_plan_rejects_implicit_or_ambiguous_inputs(targets, ports):
    with pytest.raises(ValueError):
        network_plans("standard", targets, ports)


def test_cancelled_before_admission_has_zero_coverage_and_no_jobs(tmp_path):
    runner, mid = approved(tmp_path)
    stop = Event()
    stop.set()
    with patch(
        "argos.backend.attack.recon.network.AuthorizedNmapRunner", return_value=runner
    ):
        value = run_network(
            runner.database_path,
            runner._verifier,
            mid,
            targets=("127.0.0.1",),
            ports=(80,),
            stop=stop,
        )
    assert value["status"] == "partial" and value["reason"] == "cancelled"
    assert value["coverage"]["unsubmitted_pairs"] == 1
    assert value["coverage"]["observed_pairs"] == 0
    assert network_report(runner.database_path, value["id"]) == value


def test_all_targets_checked_before_any_scan(tmp_path):
    runner, mid = approved(tmp_path)
    with (
        patch(
            "argos.backend.attack.recon.network.AuthorizedNmapRunner",
            return_value=runner,
        ),
        patch("argos.backend.attack.recon.network.ExecutionManager") as manager,
    ):
        with pytest.raises(RuntimeError, match="outside authorized scope"):
            run_network(
                runner.database_path,
                runner._verifier,
                mid,
                targets=("127.0.0.1", "10.0.0.2"),
                ports=(80,),
                profile="standard",
            )
        manager.assert_not_called()


def test_network_cli_plan_is_offline_and_scope_bound(tmp_path, capsys):
    database = tmp_path / "network.sqlite"
    assert (
        main(
            [
                "recon",
                "network-init",
                "--db",
                str(database),
                "--target-ip",
                "127.0.0.1",
                "--additional-target-ip",
                "::1",
                "--reference",
                "owned-lab",
            ]
        )
        == 0
    )
    import json

    mid = json.loads(capsys.readouterr().out)["mission_id"]
    assert (
        main(
            [
                "recon",
                "network-plan",
                "--db",
                str(database),
                "--mission-id",
                mid,
                "--targets",
                "127.0.0.1,::1",
                "--ports",
                "22,80",
                "--network-profile",
                "standard",
            ]
        )
        == 0
    )
    value = json.loads(capsys.readouterr().out)
    assert value["jobs"] == 2 and value["network_requests_sent"] == 0
    assert value["grant_verified"] is False
