"""Pure validation/building tests for authorized pivot operations."""

from core.pivot import (
    build_autoroute_command,
    build_portfwd_command,
    build_socks_proxy_command,
    validate_route,
)


def test_autoroute_builder_normalizes_network():
    route = validate_route("10.10.20.7/24")
    assert route.subnet == "10.10.20.0"
    assert route.netmask == "255.255.255.0"
    assert build_autoroute_command("10.10.20.7/24") == (
        "run post/multi/manage/autoroute CMD=add SUBNET=10.10.20.0 "
        "NETMASK=255.255.255.0"
    )


def test_port_forward_builder_and_validation():
    assert build_portfwd_command("10.10.20.9", 8080, 18080) == (
        "portfwd add -L 127.0.0.1 -l 18080 -p 8080 -r 10.10.20.9"
    )
    assert build_portfwd_command("10.10.20.9;whoami", 8080, 18080) is None
    assert build_portfwd_command("10.10.20.9", 0, 18080) is None


def test_socks_builder_does_not_offer_global_job_kill():
    command = build_socks_proxy_command(1080)
    assert "auxiliary/server/socks_proxy" in command
    assert "VERSION 5" in command
    assert build_socks_proxy_command(1080, remove=True) is None
