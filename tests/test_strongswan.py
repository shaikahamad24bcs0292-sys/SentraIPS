"""
Test strongSwan daemon status and initialization on both nodes.
"""

import subprocess


def test_strongswan_daemon_gateway_a():
    """Verify strongSwan charon daemon is alive on Gateway A."""
    res = subprocess.run(
        ["docker", "exec", "ipsec-gateway-a", "ipsec", "status"],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0, f"strongSwan status failed on Gateway A: {res.stderr}"
    assert "Security Associations" in res.stdout or "routed" in res.stdout or "0 up" in res.stdout or "conn" in res.stdout


def test_strongswan_daemon_gateway_b():
    """Verify strongSwan charon daemon is alive on Gateway B."""
    res = subprocess.run(
        ["docker", "exec", "ipsec-gateway-b", "ipsec", "status"],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0, f"strongSwan status failed on Gateway B: {res.stderr}"
    assert "Security Associations" in res.stdout or "routed" in res.stdout or "0 up" in res.stdout or "conn" in res.stdout
