"""
Test controlled traffic transmission through the IPsec tunnel.
"""

import json
import subprocess
import time
from testbed.config_generator import IPsecConfig


def setup_module():
    """Ensure tunnel is established before running traffic tests."""
    from testbed.orchestrator import TestbedOrchestrator
    orchestrator = TestbedOrchestrator()
    config = IPsecConfig(
        capture_id="traffic_test_suite",
        encryption="AES-256-GCM",
        dh_group=19,
        pfs=True,
    )
    orchestrator.apply_config(config)
    orchestrator.establish_tunnel()
    time.sleep(1)


def teardown_module():
    """Tear down tunnel after traffic tests."""
    from testbed.orchestrator import TestbedOrchestrator
    orchestrator = TestbedOrchestrator()
    orchestrator.teardown_tunnel()


def parse_json(stdout: str) -> dict:
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start != -1 and end != -1:
        return json.loads(stdout[start:end+1])
    return json.loads(stdout)


def test_icmp_traffic():
    """Verify ICMP ping traffic passes through the IPsec tunnel."""
    cmd = [
        "docker", "exec", "ipsec-gateway-a",
        "python3", "/app/testbed/traffic_generator.py",
        "--type", "icmp",
        "--target", "10.10.2.1",
        "--source", "10.10.1.1",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Traffic command failed: {res.stderr}"
    data = parse_json(res.stdout)
    assert data["success"] is True, f"ICMP ping failed: {data}"
    assert data["packets_sent"] > 0


def test_web_http_traffic():
    """Verify Web HTTP requests (GET/POST) pass through the IPsec tunnel."""
    cmd = [
        "docker", "exec", "ipsec-gateway-a",
        "python3", "/app/testbed/traffic_generator.py",
        "--type", "web",
        "--target", "10.10.2.1",
        "--source", "10.10.1.1",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Traffic command failed: {res.stderr}"
    data = parse_json(res.stdout)
    assert data["success"] is True, f"Web traffic failed: {data}"
    assert data["successful_requests"] > 0
    assert data["bytes_transferred"] > 0


def test_video_bulk_traffic():
    """Verify Video / Bulk streaming traffic passes through the IPsec tunnel."""
    cmd = [
        "docker", "exec", "ipsec-gateway-a",
        "python3", "/app/testbed/traffic_generator.py",
        "--type", "video",
        "--target", "10.10.2.1",
        "--source", "10.10.1.1",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Traffic command failed: {res.stderr}"
    data = parse_json(res.stdout)
    assert data["success"] is True, f"Video/Bulk streaming failed: {data}"
    assert data["total_bytes"] > 0


def test_voip_traffic_structure():
    """Verify VoIP RTP-like UDP traffic structure transmits through the IPsec tunnel."""
    cmd = [
        "docker", "exec", "ipsec-gateway-a",
        "python3", "/app/testbed/traffic_generator.py",
        "--type", "voip",
        "--target", "10.10.2.1",
        "--source", "10.10.1.1",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Traffic command failed: {res.stderr}"
    data = parse_json(res.stdout)
    assert data["success"] is True, f"VoIP traffic failed: {data}"
    assert data["packets_sent"] > 0
