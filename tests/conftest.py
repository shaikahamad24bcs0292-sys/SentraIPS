"""
Pytest configuration and fixtures for SentraIPS test suite.
"""

from pathlib import Path
import pytest
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from testbed.orchestrator import TestbedOrchestrator
from testbed.config_generator import IPsecConfig


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def orchestrator() -> TestbedOrchestrator:
    return TestbedOrchestrator()


@pytest.fixture
def default_config() -> IPsecConfig:
    return IPsecConfig(
        capture_id="test_run",
        vpn_mode="tunnel",
        ip_version="ipv4",
        encryption="AES-256-GCM",
        pfs=True,
        dh_group=19,
        traffic_type="web",
    )
