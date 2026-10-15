"""
Test Docker Compose configuration and container startup.
"""

import subprocess
from pathlib import Path


def test_docker_compose_config_valid(project_root: Path):
    """Verify docker-compose.yml has valid syntax and configuration."""
    res = subprocess.run(
        ["docker", "compose", "config"],
        cwd=project_root,
        capture_output=True,
        text=True
    )
    assert res.returncode == 0, f"docker compose config failed: {res.stderr}"
    assert "ipsec-gateway-a" in res.stdout
    assert "ipsec-gateway-b" in res.stdout
    assert "ipsec_net" in res.stdout


def test_containers_running(orchestrator):
    """Verify both gateway containers are currently running."""
    assert orchestrator.check_containers_running(), "Testbed containers are not running"
