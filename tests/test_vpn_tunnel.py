"""
Test IPsec VPN tunnel establishment and configuration flexibility.
"""

import subprocess
import time
from testbed.config_generator import IPsecConfig


def test_tunnel_establishment_aes256_gcm_pfs(orchestrator):
    """Test tunnel establishment with AES-256-GCM, DH 19, PFS enabled."""
    config = IPsecConfig(
        capture_id="test_gcm",
        encryption="AES-256-GCM",
        dh_group=19,
        pfs=True
    )
    orchestrator.apply_config(config)
    success = orchestrator.establish_tunnel()
    assert success, "Failed to establish tunnel with AES-256-GCM (PFS True, DH 19)"

    # Verify SA status in strongSwan
    res = subprocess.run(["docker", "exec", "ipsec-gateway-a", "ipsec", "status"], capture_output=True, text=True)
    assert "ESTABLISHED" in res.stdout or "1 up" in res.stdout, f"Tunnel not established: {res.stdout}"

    orchestrator.teardown_tunnel()


def test_tunnel_establishment_aes128_cbc(orchestrator):
    """Test tunnel establishment with AES-128-CBC, DH 14, PFS disabled."""
    config = IPsecConfig(
        capture_id="test_cbc",
        encryption="AES-128-CBC",
        dh_group=14,
        pfs=False
    )
    orchestrator.apply_config(config)
    success = orchestrator.establish_tunnel()
    assert success, "Failed to establish tunnel with AES-128-CBC (PFS False, DH 14)"

    # Verify SA status in strongSwan
    res = subprocess.run(["docker", "exec", "ipsec-gateway-a", "ipsec", "status"], capture_output=True, text=True)
    assert "ESTABLISHED" in res.stdout or "1 up" in res.stdout, f"Tunnel not established: {res.stdout}"

    orchestrator.teardown_tunnel()
