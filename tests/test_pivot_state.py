"""Tests for core/pivot.py pivot chain and subnet discovery — no live target."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.pivot import (
    discover_internal_subnets, PivotChain, PivotHop,
    build_autoroute_command, build_socks_proxy_command,
    validate_route,
)


def test_discover_from_ip_route():
    output = """
default via 192.168.1.1 dev eth0
10.10.10.0/24 dev eth1 proto kernel scope link src 10.10.10.100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50
"""
    subnets = discover_internal_subnets(output)
    assert any("10.10.10" in s for s in subnets)
    assert any("192.168.1" in s for s in subnets)


def test_discover_filters_loopback():
    output = "127.0.0.0/8 dev lo"
    subnets = discover_internal_subnets(output)
    assert not any("127." in s for s in subnets)


def test_discover_from_arp():
    output = """
? (10.10.10.5) at aa:bb:cc:dd:ee:ff [ether] on eth1
? (10.10.10.1) at ff:ee:dd:cc:bb:aa [ether] on eth1
"""
    subnets = discover_internal_subnets(output)
    assert any("10.10.10" in s for s in subnets)


def test_pivot_chain_add_hop():
    chain = PivotChain()
    hop = chain.add_hop("10.0.0.1", "10.10.10.0", msf_session=1,
                         handler_id="abc123", route="10.10.10.0/24")
    assert hop.hop_index == 0
    assert len(chain.hops) == 1
    assert hop.route == "10.10.10.0/24"


def test_pivot_chain_cleanup_commands():
    chain = PivotChain()
    chain.add_hop("10.0.0.1", "10.10.10.0", 1, "h1", route="10.10.10.0/24")
    chain.register_socks(1080, "job5", 0)
    cmds = chain.cleanup_commands()
    assert any("job5" in c for c in cmds)
    assert any("autoroute" in c and "delete" in c for c in cmds)


def test_pivot_chain_guard():
    chain = PivotChain()
    chain.add_hop("10.0.0.1", "10.10.10.5", 1, "h1", route="10.10.10.0/24")
    assert chain.guard_direct_access("10.10.10.5")
    assert not chain.guard_direct_access("10.20.30.40")


def test_pivot_chain_serialise():
    chain = PivotChain()
    chain.add_hop("10.0.0.1", "10.10.10.5", 1, "h1", route="10.10.10.0/24")
    d = chain.to_dict()
    chain2 = PivotChain.from_dict(d)
    assert chain2.chain_id == chain.chain_id
    assert len(chain2.hops) == 1
    assert chain2.hops[0].route == "10.10.10.0/24"


def test_build_autoroute_delete():
    cmd = build_autoroute_command("10.10.10.0/24", remove=True)
    assert cmd is not None
    assert "delete" in cmd
    assert "10.10.10.0" in cmd


def test_socks_proxy_command():
    cmd = build_socks_proxy_command(1080)
    assert cmd is not None
    assert "1080" in cmd
    assert "socks_proxy" in cmd


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS  {name}")
    print("All pivot_state tests passed.")
